def hex_to_state(hex_str: str):
    """
    Convert a 32-character hex string to a 4x4 byte matrix (state).
    Bytes are arranged in column-major order (AES convention).
    """
    if len(hex_str) != 32:
        raise ValueError("Plaintext/key must be 32 hex characters (16 bytes).")

    byte_list = bytes.fromhex(hex_str)

    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        state[row][col] = byte_list[i]

    return state


def state_to_hex(state) -> str:
    """
    Convert a 4x4 byte matrix back to a 32-character hex string,
    reading in column-major order.
    """
    bytes_out = []
    for col in range(4):
        for row in range(4):
            bytes_out.append(state[row][col])
    return ''.join(f'{b:02x}' for b in bytes_out)


def format_state_for_display(state):
    """
    Format a 4x4 state matrix as a list of lists of 2-character uppercase hex strings.
    Good for printing/display in UI.
    """
    return [[f'{state[row][col]:02X}' for col in range(4)] for row in range(4)]


def copy_state(state):
    """Create a deep copy of a state matrix."""
    return [row[:] for row in state]
