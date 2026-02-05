import re
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any


# ---------------------------
# 80-bit container
# ---------------------------

@dataclass
class Bits80:
    lo: int = 0  # 64-bit
    hi: int = 0  # 16-bit

    def reset(self) -> None:
        self.lo = 0
        self.hi = 0

    def push_bit_msb(self, bit: int) -> None:
        bit &= 1
        carry = (self.lo >> 63) & 1
        self.hi = ((self.hi << 1) | carry) & 0xFFFF
        self.lo = ((self.lo << 1) | bit) & 0xFFFFFFFFFFFFFFFF

    def to_hex_be10(self) -> str:
        b = [
            (self.hi >> 8) & 0xFF, self.hi & 0xFF,
            (self.lo >> 56) & 0xFF, (self.lo >> 48) & 0xFF, (self.lo >> 40) & 0xFF, (self.lo >> 32) & 0xFF,
            (self.lo >> 24) & 0xFF, (self.lo >> 16) & 0xFF, (self.lo >> 8) & 0xFF, self.lo & 0xFF,
        ]
        return " ".join(f"{x:02X}" for x in b)

    def get(self, off: int, w: int) -> int:
        if w <= 0:
            return 0
        if off + w <= 64:
            if w == 64:
                mask = (1 << 64) - 1
            else:
                mask = (1 << w) - 1
            return (self.lo >> off) & mask
        if off >= 64:
            h_off = off - 64
            if w >= 32:
                mask = 0xFFFFFFFF
            else:
                mask = (1 << w) - 1
            return (self.hi >> h_off) & mask

        lo_w = 64 - off
        hi_w = w - lo_w
        lo_p = (self.lo >> off) & ((1 << lo_w) - 1)
        hi_p = (self.hi & ((1 << hi_w) - 1)) << lo_w
        return lo_p | hi_p


# ---------------------------
# .sub reader
# ---------------------------

def read_sub_blocks(path: str) -> List[List[int]]:
    txt = open(path, "r", encoding="utf-8", errors="replace").read()
    lines = re.findall(r"^RAW_Data:\s*(.+)$", txt, flags=re.MULTILINE)
    blocks: List[List[int]] = []

    for line in lines:
        line = line.replace("...", " ")
        nums = [int(x) for x in re.findall(r"-?\d+", line)]
        nums = [v for v in nums if abs(v) >= 5]
        if len(nums) >= 16:
            blocks.append(nums)

    if not blocks:
        raise ValueError("Keine RAW_Data Blöcke gefunden (oder zu kurz).")
    return blocks


# ---------------------------
# Signal processing
# ---------------------------

def to_levels(nums: List[int], pos_is_high: bool) -> List[Tuple[bool, int]]:
    out = []
    for v in nums:
        is_high = (v > 0) if pos_is_high else (v < 0)
        out.append((is_high, abs(v)))
    return out


def expand_units(levels: List[Tuple[bool, int]], T_us: int) -> List[Tuple[bool, int]]:
    seq = []
    for is_h, dur in levels:
        units = max(1, int(round(dur / T_us)))
        seq.append((is_h, units))
    return seq


def flatten_units(seq: List[Tuple[bool, int]]) -> List[bool]:
    units: List[bool] = []
    for is_h, u in seq:
        units.extend([is_h] * u)
    return units


def scan_manchester(units: List[bool], start_unit: int, target_bits: int = 80) -> Tuple[List[int], int]:
    bits_dir: List[int] = []
    i = start_unit
    n = len(units)

    while i + 1 < n:
        u1 = units[i]
        u2 = units[i + 1]

        if u1 == u2:
            break

        dir_bit = 1 if (u1 is True and u2 is False) else 0
        bits_dir.append(dir_bit)
        i += 2

        if len(bits_dir) >= target_bits:
            break

    return bits_dir, i


def build_bits80(bits_msb: List[int]) -> Bits80:
    b = Bits80()
    b.reset()
    for bit in bits_msb:
        b.push_bit_msb(bit)
    return b


def ford_fields(b: Bits80) -> Dict[str, str]:
    key8 = (((b.hi & 0xFFFF) << 48) | ((b.lo >> 16) & 0xFFFFFFFFFFFF)) & ((1 << 64) - 1)
    key8_s = " ".join(f"{(key8 >> (8*(7-i))) & 0xFF:02X}" for i in range(8))
    key2_s = f"{(b.lo >> 8) & 0xFF:02X} {b.lo & 0xFF:02X}"

    return {
        "Key": key8_s,
        "Key_2": key2_s,
        "Serial": f"0x{b.get(16, 32):08X}",
        "Btn": f"0x{b.get(48, 4):X}",
        "Cnt": f"0x{b.get(52, 16):04X}",
        "Bs": f"0x{b.get(68, 8):02X}",
        "CRC4": f"0x{b.get(76, 4):X}",
    }


# ---------------------------
# Top-level decode
# ---------------------------

def decode_file(path: str, T_us: int = 250, max_start: int = 10000) -> List[Dict[str, Any]]:
    blocks = read_sub_blocks(path)
    found: List[Dict[str, Any]] = []

    for bi, nums in enumerate(blocks):
        for pos_is_high in [True]: 
            levels = to_levels(nums, pos_is_high)
            seq = expand_units(levels, T_us)
            units = flatten_units(seq)

            for phase in [0]:
                limit = min(len(units) - 160, max_start)
                for start in range(0, max(0, limit)):
                    dir_bits, _ = scan_manchester(units, start + phase, 80)
                    if len(dir_bits) != 80:
                        continue

                    for invert in [True]: 
                        bits = dir_bits[:]
                        if invert:
                            bits = [b ^ 1 for b in bits]

                        b80 = build_bits80(bits)
                        if b80.lo == 0 and b80.hi == 0:
                            continue

                        rec = {
                            "block": bi,
                            "polarity_posIsHigh": pos_is_high,
                            "T_us": T_us,
                            "phase": phase,
                            "start_unit": start + phase,
                            "invert": invert,
                            "hex10": b80.to_hex_be10(),
                            "fields": ford_fields(b80),
                        }
                        found.append(rec)

                    start += 10 

    uniq: List[Dict[str, Any]] = []
    seen = set()
    for r in found:
        k = r["hex10"]
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)

    return uniq


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python Fordv0.py <file.sub>")
        raise SystemExit(2)

    frames = decode_file(sys.argv[1], T_us=250)
    if not frames:
        print("Keine 80-Bit-Manchester-Frames gefunden.")
        raise SystemExit(1)

    for i, r in enumerate(frames, 1):
        f = r["fields"]
        print(f"=== Frame #{i} (Block {r['block']}) ===")
        print(f"T≈{r['T_us']}us  posIsHigh={r['polarity_posIsHigh']} phase={r['phase']} invert={r['invert']} start={r['start_unit']}")
        print(f"Key (10B BE): {r['hex10']}")
        print(f"Key   : {f['Key']}   Key_2: {f['Key_2']}")

        print(f"Serial: {f['Serial']}  Btn: {f['Btn']}  Cnt: {f['Cnt']}  Bs: {f['Bs']}  CRC4: {f['CRC4']}\n")

