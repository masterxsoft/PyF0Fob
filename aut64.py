# -*- coding: utf-8 -*-
"""
AUT64 block cipher (8-byte block, 8-nibble key schedule)

Implements:
- Aut64Key (index, key[8 nibbles], pbox[8], sbox[16 nibbles])
- aut64_encrypt(key, message8) -> bytes (8)
- aut64_decrypt(key, message8) -> bytes (8)
- aut64_pack(key) -> bytes (16)
- aut64_unpack(packed16) -> Aut64Key
"""

from dataclasses import dataclass
from typing import List, Sequence, Union

AUT64_NUM_ROUNDS = 12
AUT64_BLOCK_SIZE = 8
AUT64_KEY_SIZE = 8
AUT64_PBOX_SIZE = 8
AUT64_SBOX_SIZE = 16
AUT64_KEY_STRUCT_PACKED_SIZE = 16


TABLE_LN: List[List[int]] = [
    [0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3],  # Round 0
    [0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2],  # Round 1
    [0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1],  # Round 2
    [0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0],  # Round 3
    [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7],  # Round 4
    [0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6],  # Round 5
    [0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5],  # Round 6
    [0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4],  # Round 7
    [0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2],  # Round 8
    [0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3],  # Round 9
    [0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0],  # Round 10
    [0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1],  # Round 11
]

TABLE_UN: List[List[int]] = [
    [0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6],  # Round 0
    [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7],  # Round 1
    [0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4],  # Round 2
    [0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5],  # Round 3
    [0x5, 0x4, 0x7, 0x6, 0x1, 0x0, 0x3, 0x2],  # Round 4
    [0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3],  # Round 5
    [0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0],  # Round 6
    [0x6, 0x7, 0x4, 0x5, 0x2, 0x3, 0x0, 0x1],  # Round 7
    [0x3, 0x2, 0x1, 0x0, 0x7, 0x6, 0x5, 0x4],  # Round 8
    [0x2, 0x3, 0x0, 0x1, 0x6, 0x7, 0x4, 0x5],  # Round 9
    [0x1, 0x0, 0x3, 0x2, 0x5, 0x4, 0x7, 0x6],  # Round 10
    [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7],  # Round 11
]

TABLE_OFFSET: List[int] = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD,
    0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2,
    0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9,
    0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6,
    0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4,
    0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB,
    0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1,
    0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE,
    0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC,
    0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3,
    0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8,
    0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7,
    0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5,
    0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA,
]

TABLE_SUB: List[int] = [0x0, 0x1, 0x9, 0xE, 0xD, 0xB, 0x7, 0x6, 0xF, 0x2, 0xC, 0x5, 0xA, 0x4, 0x3, 0x8]


# --- Data model ---

@dataclass(frozen=True)
class Aut64Key:
    """
    index: 0..255
    key: 8 nibbles (each 0..15)
    pbox: 8 entries, permutation of 0..7
    sbox: 16 nibbles (each 0..15)
    """
    index: int
    key: List[int]
    pbox: List[int]
    sbox: List[int]

    def __post_init__(self) -> None:
        _validate_key(self)


BytesLike = Union[bytes, bytearray, memoryview]


# --- Internal helpers ---

def _validate_key(k: Aut64Key) -> None:
    if not (0 <= k.index <= 0xFF):
        raise ValueError("index must be 0..255")
    if len(k.key) != AUT64_KEY_SIZE:
        raise ValueError("key must have 8 nibbles")
    if len(k.pbox) != AUT64_PBOX_SIZE:
        raise ValueError("pbox must have 8 entries")
    if len(k.sbox) != AUT64_SBOX_SIZE:
        raise ValueError("sbox must have 16 nibbles")

    for v in k.key:
        if not (0 <= v <= 0xF):
            raise ValueError("key nibbles must be 0..15")
    for v in k.sbox:
        if not (0 <= v <= 0xF):
            raise ValueError("sbox nibbles must be 0..15")
    for v in k.pbox:
        if not (0 <= v <= 7):
            raise ValueError("pbox entries must be 0..7")
    if sorted(k.pbox) != list(range(8)):
        raise ValueError("pbox must be a permutation of 0..7")


def _reverse_box(box: Sequence[int], length: int) -> List[int]:
    reversed_box = [0] * length
    for i in range(length):
        for j in range(length):
            if box[j] == i:
                reversed_box[i] = j
                break
    return reversed_box


def _key_nibble(key: Aut64Key, nibble: int, table: Sequence[int], iteration: int) -> int:
    key_value = key.key[table[iteration]] & 0xF
    offset = ((key_value << 4) | (nibble & 0xF)) & 0xFF
    return TABLE_OFFSET[offset] & 0xF


def _round_key(key: Aut64Key, state: Sequence[int], round_n: int) -> int:
    result_hi = 0
    result_lo = 0
    for i in range(AUT64_BLOCK_SIZE - 1):  # 0..6
        result_hi ^= _key_nibble(key, (state[i] >> 4) & 0xF, TABLE_UN[round_n], i)
        result_lo ^= _key_nibble(key, state[i] & 0xF, TABLE_LN[round_n], i)
    return ((result_hi & 0xF) << 4) | (result_lo & 0xF)


def _final_byte_nibble(key: Aut64Key, table: Sequence[int]) -> int:
    key_value = key.key[table[AUT64_BLOCK_SIZE - 1]] & 0xF
    return (TABLE_SUB[key_value] & 0xF) << 4


def _encrypt_final_byte_nibble(key: Aut64Key, nibble: int, table: Sequence[int]) -> int:
    offset = _final_byte_nibble(key, table)
    for i in range(16):
        if TABLE_OFFSET[offset + i] == (nibble & 0xF):
            break
    return i


def _encrypt_compress(key: Aut64Key, state: Sequence[int], round_n: int) -> int:
    round_key = _round_key(key, state, round_n)
    result_hi = (round_key >> 4) & 0xF
    result_lo = round_key & 0xF

    result_hi ^= _encrypt_final_byte_nibble(key, (state[AUT64_BLOCK_SIZE - 1] >> 4) & 0xF, TABLE_UN[round_n])
    result_lo ^= _encrypt_final_byte_nibble(key, state[AUT64_BLOCK_SIZE - 1] & 0xF, TABLE_LN[round_n])

    return ((result_hi & 0xF) << 4) | (result_lo & 0xF)


def _decrypt_final_byte_nibble(key: Aut64Key, nibble: int, table: Sequence[int], result: int) -> int:
    offset = _final_byte_nibble(key, table)
    return TABLE_OFFSET[((result ^ (nibble & 0xF)) + offset) & 0xFF] & 0xF


def _decrypt_compress(key: Aut64Key, state: Sequence[int], round_n: int) -> int:
    round_key = _round_key(key, state, round_n)
    result_hi = (round_key >> 4) & 0xF
    result_lo = round_key & 0xF

    result_hi = _decrypt_final_byte_nibble(key, (state[AUT64_BLOCK_SIZE - 1] >> 4) & 0xF, TABLE_UN[round_n], result_hi)
    result_lo = _decrypt_final_byte_nibble(key, state[AUT64_BLOCK_SIZE - 1] & 0xF, TABLE_LN[round_n], result_lo)

    return ((result_hi & 0xF) << 4) | (result_lo & 0xF)


def _substitute(key: Aut64Key, byte: int) -> int:
    return ((key.sbox[(byte >> 4) & 0xF] & 0xF) << 4) | (key.sbox[byte & 0xF] & 0xF)


def _permute_bytes(key: Aut64Key, state: bytearray) -> None:
    result = bytearray(AUT64_PBOX_SIZE)
    for i in range(AUT64_PBOX_SIZE):
        result[key.pbox[i]] = state[i] & 0xFF
    state[:] = result


def _permute_bits(key: Aut64Key, byte: int) -> int:
    result = 0
    for i in range(8):
        if byte & (1 << i):
            result |= (1 << (key.pbox[i] & 7))
    return result & 0xFF


# --- Public API (encrypt/decrypt/pack/unpack) ---

def aut64_encrypt(key: Aut64Key, message: BytesLike) -> bytes:
    """
    Encrypt a single 8-byte block.

    Args:
        key: Aut64Key
        message: 8 bytes-like object

    Returns:
        ciphertext: 8 bytes
    """
    if len(message) != AUT64_BLOCK_SIZE:
        raise ValueError("message must be exactly 8 bytes")

    # Build reverse_key
    reverse_key = Aut64Key(
        index=key.index,
        key=list(key.key),
        pbox=_reverse_box(key.pbox, AUT64_PBOX_SIZE),
        sbox=_reverse_box(key.sbox, AUT64_SBOX_SIZE),
    )

    state = bytearray(message)
    for rnd in range(AUT64_NUM_ROUNDS):
        _permute_bytes(reverse_key, state)
        state[7] = _encrypt_compress(reverse_key, state, rnd)
        state[7] = _substitute(reverse_key, state[7])
        state[7] = _permute_bits(reverse_key, state[7])
        state[7] = _substitute(reverse_key, state[7])

    return bytes(state)


def aut64_decrypt(key: Aut64Key, message: BytesLike) -> bytes:
    """
    Decrypt a single 8-byte block.

    Args:
        key: Aut64Key
        message: 8 bytes-like object

    Returns:
        plaintext: 8 bytes
    """
    if len(message) != AUT64_BLOCK_SIZE:
        raise ValueError("message must be exactly 8 bytes")

    state = bytearray(message)
    for rnd in range(AUT64_NUM_ROUNDS - 1, -1, -1):
        state[7] = _substitute(key, state[7])
        state[7] = _permute_bits(key, state[7])
        state[7] = _substitute(key, state[7])
        state[7] = _decrypt_compress(key, state, rnd)
        _permute_bytes(key, state)

    return bytes(state)


def aut64_pack(key: Aut64Key) -> bytes:
    """
    Pack Aut64Key into 16 bytes.
    """
    dest = bytearray(AUT64_KEY_STRUCT_PACKED_SIZE)
    dest[0] = key.index & 0xFF

    # key (8 nibbles) -> 4 bytes
    for i in range(AUT64_KEY_SIZE // 2):
        dest[i + 1] = ((key.key[i * 2] & 0xF) << 4) | (key.key[i * 2 + 1] & 0xF)

    # pbox (8 * 3 bits) -> 3 bytes at dest[5..7]
    pbox_val = 0
    for i in range(AUT64_PBOX_SIZE):
        pbox_val = ((pbox_val << 3) | (key.pbox[i] & 0x7)) & 0xFFFFFFFF
    dest[5] = (pbox_val >> 16) & 0xFF
    dest[6] = (pbox_val >> 8) & 0xFF
    dest[7] = pbox_val & 0xFF

    # sbox (16 nibbles) -> 8 bytes at dest[8..15]
    for i in range(AUT64_SBOX_SIZE // 2):
        dest[i + 8] = ((key.sbox[i * 2] & 0xF) << 4) | (key.sbox[i * 2 + 1] & 0xF)

    return bytes(dest)


def aut64_unpack(src: BytesLike) -> Aut64Key:
    """
    Unpack 16 bytes into Aut64Key.
    """
    if len(src) != AUT64_KEY_STRUCT_PACKED_SIZE:
        raise ValueError("src must be exactly 16 bytes")

    src_b = bytes(src)
    index = src_b[0]

    key_nibbles = [0] * AUT64_KEY_SIZE
    for i in range(AUT64_KEY_SIZE // 2):
        b = src_b[i + 1]
        key_nibbles[i * 2] = (b >> 4) & 0xF
        key_nibbles[i * 2 + 1] = b & 0xF

    pbox_val = ((src_b[5] << 16) | (src_b[6] << 8) | src_b[7]) & 0xFFFFFFFF
    pbox = [0] * AUT64_PBOX_SIZE
    for i in range(AUT64_PBOX_SIZE - 1, -1, -1):
        pbox[i] = pbox_val & 0x7
        pbox_val >>= 3

    sbox = [0] * AUT64_SBOX_SIZE
    for i in range(AUT64_SBOX_SIZE // 2):
        b = src_b[i + 8]
        sbox[i * 2] = (b >> 4) & 0xF
        sbox[i * 2 + 1] = b & 0xF

    return Aut64Key(index=index, key=key_nibbles, pbox=pbox, sbox=sbox)


# --- Minimal self-test (roundtrip) ---

def _self_test() -> None:
    # Arbitrary but valid key material (nibbles/permutations)
    k = Aut64Key(
        index=0x01,
        key=[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8],
        pbox=[4, 5, 6, 7, 0, 1, 2, 3],
        sbox=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    )
    pt = bytes([0,1,2,3,4,5,6,7])
    ct = aut64_encrypt(k, pt)
    rt = aut64_decrypt(k, ct)
    if rt != pt:
        raise AssertionError("AUT64 self-test failed (decrypt(encrypt(pt)) != pt)")


if __name__ == "__main__":
    _self_test()
    print("AUT64 self-test OK")
