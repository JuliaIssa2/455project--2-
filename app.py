from flask import Flask, render_template, request
from aes.aes_core import encrypt_block
from aes.decrypt_core import decrypt_block
from aes.state import format_state_for_display

app = Flask(__name__)

# -------------------------
# Helpers: bytes/hex/pad
# -------------------------
def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def pkcs7_pad(block_bytes: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(block_bytes) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return block_bytes + bytes([pad_len]) * pad_len

def pkcs7_unpad(padded: bytes) -> bytes:
    if len(padded) == 0 or len(padded) % 16 != 0:
        raise ValueError("Invalid padded length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return padded[:-pad_len]

def chunk_bytes(b: bytes, size: int = 16):
    for i in range(0, len(b), size):
        yield b[i:i+size]


# -------------------------
# Multi-block wrappers
# -------------------------
def encrypt_any_text_debug(plain_text: str, key_hex: str):
    plain_bytes = plain_text.encode('utf-8')
    padded = pkcs7_pad(plain_bytes, 16)

    ciphertext_hex_blocks = []
    blocks_debug = []

    for idx, blk in enumerate(chunk_bytes(padded, 16)):
        blk_hex = bytes_to_hex(blk).upper()
        ct_hex, round_states, round_keys = encrypt_block(blk_hex, key_hex)
        ciphertext_hex_blocks.append(ct_hex)

        rounds = []
        for r in range(len(round_states)):
            rounds.append({
                "round_num": r,
                "state": format_state_for_display(round_states[r]),
                "key": format_state_for_display(round_keys[r])
            })

        blocks_debug.append({
            "index": idx,
            "input_block": blk_hex,
            "output_block": ct_hex,
            "rounds": rounds
        })

    full_cipher_hex = ''.join(ciphertext_hex_blocks).upper()
    return full_cipher_hex, blocks_debug


def decrypt_any_hex_debug(cipher_hex_full: str, key_hex: str):
    h = cipher_hex_full.replace(' ', '').strip().upper()
    if len(h) == 0 or len(h) % 32 != 0:
        raise ValueError("Ciphertext hex must be non-empty and a multiple of 32 hex characters (16 bytes per block).")

    plaintext_bytes_blocks = []
    blocks_debug = []

    for idx in range(0, len(h), 32):
        blk_hex = h[idx:idx+32]
        pt_hex, round_states, round_keys = decrypt_block(blk_hex, key_hex)
        plaintext_bytes_blocks.append(bytes.fromhex(pt_hex))

        rounds = []
        for r in range(len(round_states)):
            rounds.append({
                "round_num": r,
                "state": format_state_for_display(round_states[r]),
                "key": format_state_for_display(round_keys[r])
            })

        blocks_debug.append({
            "index": idx // 32,
            "input_block": blk_hex,
            "output_block": pt_hex,
            "rounds": rounds
        })

    combined = b''.join(plaintext_bytes_blocks)
    unpadded = pkcs7_unpad(combined)
    try:
        decoded = unpadded.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        decoded = unpadded.decode('utf-8', errors='replace')

    return decoded, blocks_debug


# -------------------------
# Flask route
# -------------------------
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    input_text = ''
    input_key = ''
    mode = 'encrypt'

    if request.method == 'POST':
        mode = request.form.get("mode", "encrypt")
        input_text = request.form.get("plaintext", "")  # arbitrary text for encrypt, hex for decrypt
        key_hex = request.form.get("key", "").strip().upper()
        input_key = key_hex

        # Validate key is hex and length 32
        try:
            int(key_hex.replace(" ", ""), 16)
        except Exception:
            error = "Key must be hexadecimal characters only (0-9, A-F)."
            return render_template("index.html", error=error, input_plaintext=input_text, input_key=input_key, mode=mode)

        if len(key_hex.replace(" ", "")) != 32:
            error = "Key must be exactly 32 hex characters (128-bit)."
            return render_template("index.html", error=error, input_plaintext=input_text, input_key=input_key, mode=mode)

        try:
            if mode == "encrypt":
                ciphertext_hex, blocks_debug = encrypt_any_text_debug(input_text, key_hex)
                label = "Ciphertext (hex)"
                result = {
                    "label": label,
                    "output": ciphertext_hex,
                    "blocks": blocks_debug
                }
            else:
                cipher_hex_clean = input_text.replace(' ', '').strip()
                int(cipher_hex_clean, 16)  # will raise if not valid hex
                decoded_text, blocks_debug = decrypt_any_hex_debug(cipher_hex_clean, key_hex)
                label = "Recovered Plaintext (UTF-8)"
                result = {
                    "label": label,
                    "output": decoded_text,
                    "blocks": blocks_debug
                }
        except ValueError as e:
            error = f"Error: {str(e)}"
        except Exception as e:
            error = f"Unexpected error: {str(e)}"

    return render_template("index.html",
                           result=result,
                           error=error,
                           input_plaintext=input_text,
                           input_key=input_key,
                           mode=mode)


if __name__ == "__main__":
    app.run(debug=True)
