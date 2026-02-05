#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
from dataclasses import dataclass
from collections import Counter
from aut64 import aut64_unpack, aut64_decrypt

AUT64_key = aut64_unpack(bytes.fromhex("038AA37B1E561F8384B619C52E0A3FD7"))

# --- constants  ---
TE_SHORT = 500
TE_LONG  = 1000
TE_DELTA = 120
MIN_BITS = 80
TE_MED   = (TE_SHORT + TE_LONG) // 2
TE_END   = TE_LONG * 5


def is_close(d, t, delta=TE_DELTA):
    return abs(d - t) < delta


# --- manchester state machine  ---
class ManchesterState:
    Mid0 = 0
    Mid1 = 1
    Start1 = 2
    Start0 = 3


class ManchesterEvent:
    Reset = 0
    ShortHigh = 1
    ShortLow = 2
    LongHigh = 3
    LongLow = 4


def vw_manchester_advance(state, event):
    # returns (next_state, produced_bit, bit_value)
    if event == ManchesterEvent.Reset:
        return ManchesterState.Mid1, False, None

    if state == ManchesterState.Mid0 or state == ManchesterState.Mid1:
        if event == ManchesterEvent.ShortHigh:
            return ManchesterState.Start1, False, None
        if event == ManchesterEvent.ShortLow:
            return ManchesterState.Start0, False, None
        return ManchesterState.Mid1, False, None

    if state == ManchesterState.Start1:
        if event == ManchesterEvent.ShortLow:
            return ManchesterState.Mid1, True, True
        if event == ManchesterEvent.LongLow:
            return ManchesterState.Start0, True, True
        return ManchesterState.Mid1, False, None

    # state == Start0
    if event == ManchesterEvent.ShortHigh:
        return ManchesterState.Mid0, True, False
    if event == ManchesterEvent.LongHigh:
        return ManchesterState.Start1, True, False

    return ManchesterState.Mid1, False, None


# --- bit mapping  ---
def vw_get_bit_index(bit_full):
    if 8 <= bit_full < 72:
        return bit_full - 8
    if bit_full >= 72:
        return (bit_full - 64) | 0x80
    return bit_full | 0x80


def vw_button_name(btn):
    return {
        0x1: "UNLOCK",
        0x2: "LOCK",
        0x3: "UN+LOCK",
        0x4: "TRUNK",
        0x5: "UN+TRUNK",
        0x6: "LOCK+TRUNK",
        0x7: "UN+LOCK+TRUNK",
        0x8: "PANIC",
    }.get(btn, "UNKNOWN")


@dataclass
class VWFrame:
    type_byte: int
    key_high: int
    key_low: int
    check: int

    def bytes10(self):
        return bytes([
            self.type_byte & 0xFF,
            (self.key_high >> 24) & 0xFF,
            (self.key_high >> 16) & 0xFF,
            (self.key_high >>  8) & 0xFF,
            (self.key_high >>  0) & 0xFF,
            (self.key_low  >> 24) & 0xFF,
            (self.key_low  >> 16) & 0xFF,
            (self.key_low  >>  8) & 0xFF,
            (self.key_low  >>  0) & 0xFF,
            self.check & 0xFF,
        ])

    # Key1 = first 8 bytes, Key2 = last 2 bytes, CRC = last byte
    def key1_hex(self):
        return self.bytes10()[0:8].hex().upper()

    def key2_hex(self):
        return self.bytes10()[8:10].hex().upper()

    def crc_hex(self):
        return "%02X" % (self.bytes10()[9],)

    def btn(self):
        return (self.check >> 4) & 0xF

    def btn_name(self):
        return vw_button_name(self.btn())


class DecoderStep:
    Reset = 0
    Sync  = 1
    S1    = 2
    S2    = 3
    S3    = 4
    Data  = 5


# =========================
# THIS is the VWDecoder class (exists + used)
# =========================
class VWDecoder:
    def __init__(self):
        self.reset()

    def reset(self):
        self.step = DecoderStep.Reset
        self.state = ManchesterState.Mid1
        self.data = 0
        self.data2 = 0
        self.count = 0

    def add_bit(self, bit):
        idx_full = (MIN_BITS - 1) - self.count  # 79..0
        m = vw_get_bit_index(idx_full)
        pos = m & 0x7F

        if (m & 0x80) != 0:
            if bit:
                self.data2 |= (1 << pos)
            else:
                self.data2 &= ~(1 << pos)
        else:
            if bit:
                self.data |= (1 << pos)
            else:
                self.data &= ~(1 << pos)

        self.count += 1

        if self.count == MIN_BITS:
            type_byte = (self.data2 >> 8) & 0xFF
            check = self.data2 & 0xFF
            key_high = (self.data >> 32) & 0xFFFFFFFF
            key_low = self.data & 0xFFFFFFFF
            return VWFrame(type_byte, key_high, key_low, check)

        return None

    def feed(self, level, dur):
        # RESET
        if self.step == DecoderStep.Reset:
            if is_close(dur, TE_SHORT):
                self.step = DecoderStep.Sync
            return None

        # SYNC
        if self.step == DecoderStep.Sync:
            if is_close(dur, TE_SHORT):
                return None
            if level and is_close(dur, TE_LONG):
                self.step = DecoderStep.S1
                return None
            self.reset()
            return None

        # S1
        if self.step == DecoderStep.S1:
            if (not level) and is_close(dur, TE_SHORT):
                self.step = DecoderStep.S2
                return None
            self.reset()
            return None

        # S2
        if self.step == DecoderStep.S2:
            if level and is_close(dur, TE_MED):
                self.step = DecoderStep.S3
                return None
            self.reset()
            return None

        # S3
        if self.step == DecoderStep.S3:
            if is_close(dur, TE_MED):
                return None
            if level and is_close(dur, TE_SHORT):
                self.state, _, _ = vw_manchester_advance(self.state, ManchesterEvent.Reset)
                self.state, _, _ = vw_manchester_advance(self.state, ManchesterEvent.ShortHigh)
                self.step = DecoderStep.Data
                self.count = 0
                self.data = 0
                self.data2 = 0
                return None
            self.reset()
            return None

        # DATA
        if self.step != DecoderStep.Data:
            self.reset()
            return None

        if is_close(dur, TE_SHORT):
            ev = ManchesterEvent.ShortHigh if level else ManchesterEvent.ShortLow
        elif is_close(dur, TE_LONG):
            ev = ManchesterEvent.LongHigh if level else ManchesterEvent.LongLow
        elif (self.count == (MIN_BITS - 1)) and (not level) and (dur > TE_END):
            ev = ManchesterEvent.ShortLow
        else:
            self.reset()
            return None

        self.state, produced, bit = vw_manchester_advance(self.state, ev)
        if produced:
            return self.add_bit(bool(bit))
        return None


def read_sub_pulses(path):
    pulses = []
    in_raw = False
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("RAW_Data:"):
                in_raw = True
                line = line[9:].strip()
            if in_raw:
                if not line:
                    in_raw = False
                    continue
                pulses.extend(int(x) for x in re.findall(r"-?\d+", line))
    return pulses


def main(argv):
    if len(argv) != 2:
        print("Usage: python decode.py <file.sub>")
        return 2

    pulses = read_sub_pulses(argv[1])
    if not pulses:
        print("No RAW_Data pulses found.")
        return 1

    dec = VWDecoder()
    frames = []

    for p in pulses:
        fr = dec.feed(p > 0, abs(p))
        if fr is not None:
            frames.append(fr)

    if not frames:
        print("No frames decoded.")
        return 1

    for fr in frames:
        #AUT64 DECODE
        raw  = fr.key1_hex()[2:16] + fr.key2_hex()[0:2]
        ct  = bytes.fromhex(raw)
        pt = aut64_decrypt(AUT64_key, ct)
        serial = pt[0:4] 
        tcnt = bytes([pt[5],pt[6],pt[4]]) 
        last   = pt[7] 
        
        print("Key1:%s  Key2:%s  Btn:%02X(%s)  Serial:%s  Cnt:%s  CRC:%s  LAST:%s"
              % (fr.key1_hex(), fr.key2_hex(), fr.btn(), fr.btn_name(), serial.hex(), tcnt.hex(), fr.crc_hex(), hex(last)))

    cnt = Counter((fr.key1_hex() + fr.key2_hex()) for fr in frames)
    print("\nDone! Frames: %d  Unique: %d" % (len(frames), len(cnt)))
    for hx, c in cnt.most_common(10):
        print("%3dx %s" % (c, hx))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))