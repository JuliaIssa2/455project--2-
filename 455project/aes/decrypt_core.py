from aes.tables import S_BOX, GMUL9, GMUL11, GMUL13, GMUL14
from aes.state import hex_to_state, state_to_hex, copy_state
from aes.key_schedule import expand_key

# Build inverse S-box from S_BOX
INV_S_BOX = [0] * 256
for i in range(256):
    INV_S_BOX[S_BOX[i]] = i


def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]


def inv_shift_rows(state):
    # Reverse of shift
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


def inv_mix_columns(state):
    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        state[0][col] = GMUL14[s0] ^ GMUL11[s1] ^ GMUL13[s2] ^ GMUL9[s3]
        state[1][col] = GMUL9[s0]  ^ GMUL14[s1] ^ GMUL11[s2] ^ GMUL13[s3]
        state[2][col] = GMUL13[s0] ^ GMUL9[s1]  ^ GMUL14[s2] ^ GMUL11[s3]
        state[3][col] = GMUL11[s0] ^ GMUL13[s1] ^ GMUL9[s2]  ^ GMUL14[s3]


def add_round_key(state, round_key):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]


def decrypt_block(cipher_hex: str, key_hex: str):
    if len(cipher_hex) != 32:
        raise ValueError("Ciphertext must be 32 hex characters.")

    round_keys = expand_key(key_hex)

    state = hex_to_state(cipher_hex)
    round_states = []

    add_round_key(state, round_keys[10])
    round_states.append(copy_state(state))

    # Rounds 9 → 1
    for rnd in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[rnd])
        inv_mix_columns(state)
        round_states.append(copy_state(state))

    # Round 0
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    round_states.append(copy_state(state))

    plaintext_hex = state_to_hex(state).upper()
    return plaintext_hex, round_states, round_keys
