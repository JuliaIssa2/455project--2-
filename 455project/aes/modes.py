import os

from .aes_core import encrypt_block
from .decrypt_core import decrypt_block

BLOCK_SIZE = 16  # AES block size in bytes


# -------- Key handling: user string -> 16-byte AES key (hex) --------

def normalize_key(user_key: str) -> str:
    """
    Take a normal user key string and turn it into a 16-byte AES key (hex).
    - UTF-8 encode
    - truncate or pad with zeros to 16 bytes
    - return as 32-character hex string (uppercase)
    """
    key_bytes = user_key.encode("utf-8")

    if len(key_bytes) < BLOCK_SIZE:
        key_bytes = key_bytes.ljust(BLOCK_SIZE, b"\x00")
    else:
        key_bytes = key_bytes[:BLOCK_SIZE]

    return key_bytes.hex().upper()


# -------- PKCS#7 padding --------

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Pad data so its length is a multiple of block_size using PKCS#7.
    """
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Remove PKCS#7 padding.
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding.")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding.")

    return data[:-pad_len]


# -------- AES-CBC encryption for NORMAL TEXT --------

def encrypt_text_cbc(plaintext: str, user_key: str):
    """
    Encrypt arbitrary-length text using AES-128 in CBC mode,
    built on top of your encrypt_block() (single-block AES).

    Returns:
        full_cipher_hex: IV || C1 || C2 || ... as one big hex string
        iv_hex:          IV as 32-character hex string
    """
    # 1) Normal text -> bytes
    pt_bytes = plaintext.encode("utf-8")

    # 2) Pad to multiple of 16 bytes
    pt_padded = pkcs7_pad(pt_bytes, BLOCK_SIZE)

    # 3) Convert user key -> 16-byte AES key hex
    key_hex = normalize_key(user_key)

    # 4) Generate random IV (16 bytes)
    iv = os.urandom(BLOCK_SIZE)
    iv_hex = iv.hex().upper()

    # 5) CBC over blocks
    prev_block_bytes = iv
    cipher_blocks = []

    for i in range(0, len(pt_padded), BLOCK_SIZE):
        block = pt_padded[i : i + BLOCK_SIZE]  # 16 bytes

        # XOR with previous cipher block (or IV for first block)
        xored = bytes(b ^ p for b, p in zip(block, prev_block_bytes))

        # Encrypt this 16-byte block using your AES-128 block function
        xored_hex = xored.hex().upper()
        c_hex, _, _ = encrypt_block(xored_hex, key_hex)  # we only need ciphertext

        cipher_blocks.append(c_hex)
        prev_block_bytes = bytes.fromhex(c_hex)

    # Full ciphertext as hex = IV || C1 || C2 || ...
    full_cipher_hex = iv_hex + "".join(cipher_blocks)
    return full_cipher_hex, iv_hex


# -------- AES-CBC decryption back to NORMAL TEXT --------

def decrypt_text_cbc(full_cipher_hex: str, user_key: str) -> str:
    """
    Decrypt ciphertext produced by encrypt_text_cbc and return the original text.

    full_cipher_hex is: IV || C1 || C2 || ... (all uppercase hex)
    """
    if len(full_cipher_hex) < 32 or len(full_cipher_hex) % 32 != 0:
        raise ValueError("Ciphertext hex length must be a multiple of 32 "
                         "and at least 32 (for the IV).")

    # Same key normalization as encryption
    key_hex = normalize_key(user_key)

    # 1) Extract IV (first 16 bytes = first 32 hex chars)
    iv_hex = full_cipher_hex[:32]
    iv_bytes = bytes.fromhex(iv_hex)

    # 2) Remaining ciphertext blocks
    cipher_hex = full_cipher_hex[32:]
    blocks = [cipher_hex[i : i + 32] for i in range(0, len(cipher_hex), 32)]

    prev_block_bytes = iv_bytes
    pt_padded_bytes = b""

    for c_hex in blocks:
        # Decrypt single block
        p_xor_hex, _, _ = decrypt_block(c_hex, key_hex)
        p_xor_bytes = bytes.fromhex(p_xor_hex)

        # XOR with previous cipher block to recover plaintext block
        pt_block = bytes(b ^ p for b, p in zip(p_xor_bytes, prev_block_bytes))
        pt_padded_bytes += pt_block

        prev_block_bytes = bytes.fromhex(c_hex)

    # 3) Remove padding and decode
    pt_bytes = pkcs7_unpad(pt_padded_bytes, BLOCK_SIZE)
    return pt_bytes.decode("utf-8", errors="ignore")
