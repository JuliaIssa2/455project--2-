from aes.tables import S_BOX, RCON


def expand_key(key_hex: str):
    """
    AES-128 key expansion.
    Input:  32-character hex string representing the 128-bit key.
    Output: List of 11 round keys, each as a 4x4 state matrix (column-major).
    """
    if len(key_hex) != 32:
        raise ValueError("Key must be 32 hex characters (16 bytes) for AES-128.")

    key_bytes = bytes.fromhex(key_hex)

    # Initial 4x4 key state (round 0)
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = key_bytes[i]

    round_keys = [[row[:] for row in state]]  # round 0 key

    # Generate 10 further round keys (AES-128 has 11 total: round 0..10)
    for round_num in range(10):
        # Last column of previous round key
        last_col = [state[row][3] for row in range(4)]

        # RotWord: cyclic left rotation
        last_col = last_col[1:] + last_col[:1]

        # SubWord: apply S-box to each byte
        last_col = [S_BOX[b] for b in last_col]

        # XOR with round constant
        last_col[0] ^= RCON[round_num]

        # Build new state (next round key)
        new_state = [[0] * 4 for _ in range(4)]

        # First column = previous first column XOR transformed last_col
        for row in range(4):
            new_state[row][0] = state[row][0] ^ last_col[row]

        # Next columns: each = previous column XOR same column in old key
        for col in range(1, 4):
            for row in range(4):
                new_state[row][col] = state[row][col] ^ new_state[row][col - 1]

        state = new_state
        round_keys.append([row[:] for row in state])

    return round_keys
