# aes/debug_helpers.py

from .aes_core import encrypt_block
from .decrypt_core import decrypt_block
from .state import format_state_for_display  # optional, for nicer printing


def encrypt_blocks_debug(blocks_hex, key_hex):
    """
    Encrypt a list of 16-byte blocks (each a 32-char hex string)
    and collect round states / round keys for each block.
    """
    full_cipher_hex = ""
    blocks_debug = []

    for idx, block_hex in enumerate(blocks_hex):
        # Encrypt single block with your existing AES core
        c_hex, round_states, round_keys = encrypt_block(block_hex, key_hex)

        full_cipher_hex += c_hex

        formatted_rounds = []
        for r_idx, state in enumerate(round_states):
            formatted_rounds.append({
                "round_num": r_idx,
                # you can use format_state_for_display or just state itself
                "state": format_state_for_display(state),
                "key": format_state_for_display(round_keys[r_idx]),
            })

        blocks_debug.append({
            "index": idx,
            "input_block": block_hex,
            "output_block": c_hex,
            "rounds": formatted_rounds,
        })

    return full_cipher_hex, blocks_debug


def decrypt_blocks_debug(blocks_hex, key_hex):
    """
    Decrypt a list of 16-byte blocks (each a 32-char hex string)
    and collect round states / round keys for each block.
    """
    full_plain_hex = ""
    blocks_debug = []

    for idx, block_hex in enumerate(blocks_hex):
        p_hex, round_states, round_keys = decrypt_block(block_hex, key_hex)

        full_plain_hex += p_hex

        formatted_rounds = []
        for r_idx, state in enumerate(round_states):
            formatted_rounds.append({
                "round_num": r_idx,
                "state": format_state_for_display(state),
                "key": format_state_for_display(round_keys[r_idx]),
            })

        blocks_debug.append({
            "index": idx,
            "input_block": block_hex,
            "output_block": p_hex,
            "rounds": formatted_rounds,
        })

    return full_plain_hex, blocks_debug
