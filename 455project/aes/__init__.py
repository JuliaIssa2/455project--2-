"""
AES-128 Implementation Package

Usage example:

    from aes import encrypt_block

    pt  = "00112233445566778899AABBCCDDEEFF"
    key = "000102030405060708090A0B0C0D0E0F"

    ciphertext, round_states, round_keys = encrypt_block(pt, key)
    print(ciphertext)  # 69C4E0D86A7B0430D8CDB78070B4C55A
"""

from .aes_core import encrypt_block
from .key_schedule import expand_key
from .state import hex_to_state, state_to_hex, format_state_for_display
from .modes import encrypt_text_cbc, decrypt_text_cbc


