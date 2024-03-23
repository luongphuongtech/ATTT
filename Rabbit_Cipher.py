import time
def generate_key_stream(key, iv, n):
    def g_function(x):
        c = [0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
             0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0x34D34D34]
        result = 0
        for i in range(8):
            result ^= c[i] & SBOX[(x >> (4 * i)) & 0x0F]
        return result

    state = [0] * 8
    k = [0] * 8
    for i in range(8):
        k[i] = key[i] ^ iv[i]

    for _ in range(n):
        for i in range(8):
            state[i] ^= k[i]

        for i in range(8):
            k[i] ^= state[(i + 1) % 8]

        for i in range(8):
            state[i] = (state[i] + g_function(state[(i + 2) % 8])) & 0xFFFFFFFF

        yield from state

def rabbit_encrypt(plaintext, key, iv):
    blocks = len(plaintext) // 16 + (1 if len(plaintext) % 16 != 0 else 0)  # Số lượng blocks cần mã hóa
    keystream = generate_key_stream(key, iv, blocks)
    ciphertext = bytearray()
    plaintext_index = 0
    for _ in range(blocks):
        keystream_byte = next(keystream)
        for _ in range(min(16, len(plaintext) - plaintext_index)):
            ciphertext.append(plaintext[plaintext_index] ^ (keystream_byte & 0xFF))
            keystream_byte >>= 8  # Dịch phải 8 bit để lấy byte tiếp theo của keystream
            plaintext_index += 1
    return ciphertext


def rabbit_decrypt(ciphertext, key, iv):
    blocks = len(ciphertext) // 16 + (1 if len(ciphertext) % 16 != 0 else 0)
    keystream = generate_key_stream(key, iv, blocks)
    plaintext = bytearray()
    for _ in range(blocks):
        keystream_byte = next(keystream)
        for _ in range(min(16, len(ciphertext))):  # Số lượng byte cần giải mã tối đa là 16 hoặc ít hơn
            plaintext.append(ciphertext.pop(0) ^ (keystream_byte & 0xFF))
            keystream_byte >>= 8  # Dịch phải 8 bit để lấy byte tiếp theo của keystream
    return plaintext

# SBOX definition
SBOX = [
    0x6, 0x4, 0xC, 0x5, 0x0, 0x7, 0x2, 0xE,
    0x1, 0xF, 0x3, 0xD, 0x8, 0xA, 0x9, 0xB
]

# Example usage:
key = [0x00] * 16  # 128-bit key
iv = [0x00] * 8  # 64-bit IV
plaintext = b"Hello, Rabbit!"
ciphertext = rabbit_encrypt(plaintext, key, iv)
decrypted_text = rabbit_decrypt(ciphertext, key, iv)
print("Original:", plaintext)
print("Encrypted:", ciphertext)
print("Decrypted:", decrypted_text.decode())