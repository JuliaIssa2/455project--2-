from aes.tables import S_BOX, GMUL2, GMUL3
from aes.state import hex_to_state, state_to_hex, copy_state
from aes.key_schedule import expand_key


def sub_bytes(state):
    """SubBytes: apply S-box to every byte in the state."""
    for row in range(4):
        for col in range(4):
            state[row][col] = S_BOX[state[row][col]]


def shift_rows(state):
    """
    ShiftRows transformation:
    - Row 0: no shift
    - Row 1: shift left by 1
    - Row 2: shift left by 2
    - Row 3: shift left by 3
    """
    # Row 1
    state[1] = state[1][1:] + state[1][:1]
    # Row 2
    state[2] = state[2][2:] + state[2][:2]
    # Row 3
    state[3] = state[3][3:] + state[3][:3]


def mix_columns(state):
    """
    MixColumns transformation:
    Each column is multiplied by the fixed AES matrix in GF(2^8):

    [02 03 01 01]
    [01 02 03 01]
    [01 01 02 03]
    [03 01 01 02]
    """
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        state[0][col] = GMUL2[s0] ^ GMUL3[s1] ^ s2 ^ s3
        state[1][col] = s0 ^ GMUL2[s1] ^ GMUL3[s2] ^ s3
        state[2][col] = s0 ^ s1 ^ GMUL2[s2] ^ GMUL3[s3]
        state[3][col] = GMUL3[s0] ^ s1 ^ s2 ^ GMUL2[s3]


def add_round_key(state, round_key):
    """XOR the state with a 4x4 round key matrix."""
    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]


def encrypt_block(plaintext_hex: str, key_hex: str):
    """
    AES-128 encryption of a single 16-byte block.

    Inputs:
        plaintext_hex: 32-character hex string (128-bit plaintext)
        key_hex:       32-character hex string (128-bit key)

    Returns:
        ciphertext_hex (uppercase),
        round_states: list of 4x4 state matrices after each round (0..10),
        round_keys:   list of 4x4 round key matrices (0..10)
    """
    if len(plaintext_hex) != 32:
        raise ValueError("Plaintext must be 32 hex characters (16 bytes).")
    if len(key_hex) != 32:
        raise ValueError("Key must be 32 hex characters (16 bytes) for AES-128.")

    # Expand key into 11 round keys
    round_keys = expand_key(key_hex)

    # Convert plaintext to initial state
    state = hex_to_state(plaintext_hex)

    # To store state after each round for visualization
    round_states = []

    # Round 0: initial AddRoundKey with round key 0
    add_round_key(state, round_keys[0])
    round_states.append(copy_state(state))

    # Rounds 1-9 (full rounds)
    for round_num in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_num])
        round_states.append(copy_state(state))

    # Round 10 (final round: no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    round_states.append(copy_state(state))

    # Convert final state to ciphertext hex (uppercase for display)
    ciphertext_hex = state_to_hex(state).upper()

    return ciphertext_hex, round_states, round_keys
