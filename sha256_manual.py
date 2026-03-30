NUM_ROUNDS = 64

# First 32 bits of the fractional parts of the square roots of the first 8 primes
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# First 32 bits of the fractional parts of the cube roots of the first 64 primes
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

MASK = 0xffffffff


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def shr(x, n):
    return x >> n


def ch(x, y, z):
    return (x & y) ^ (~x & z) & MASK


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def pad_message(message: bytes) -> bytes:
    """Pad message to a multiple of 512 bits (64 bytes) per SHA-256 spec."""
    msg_len = len(message)
    bit_len = msg_len * 8
    # Append 0x80 byte
    message += b'\x80'
    # Pad with zeros until length ≡ 56 mod 64
    while len(message) % 64 != 56:
        message += b'\x00'
    # Append original length as 64-bit big-endian
    message += bit_len.to_bytes(8, 'big')
    return message


def process_block(block: bytes, h_state: list, num_rounds: int = NUM_ROUNDS) -> list:
    """Process a single 512-bit (64-byte) block."""
    # Prepare message schedule
    w = []
    for i in range(16):
        w.append(int.from_bytes(block[i * 4:(i + 1) * 4], 'big'))
    for i in range(16, num_rounds):
        w.append((sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16]) & MASK)

    a, b, c, d, e, f, g, h = h_state

    for i in range(num_rounds):
        t1 = (h + Sigma1(e) + ch(e, f, g) + K[i] + w[i]) & MASK
        t2 = (Sigma0(a) + maj(a, b, c)) & MASK
        h = g
        g = f
        f = e
        e = (d + t1) & MASK
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK

    return [
        (h_state[0] + a) & MASK,
        (h_state[1] + b) & MASK,
        (h_state[2] + c) & MASK,
        (h_state[3] + d) & MASK,
        (h_state[4] + e) & MASK,
        (h_state[5] + f) & MASK,
        (h_state[6] + g) & MASK,
        (h_state[7] + h) & MASK,
    ]


def sha256(message: str, num_rounds: int = NUM_ROUNDS) -> str:
    """Compute SHA-256 hash of a string. Returns hex digest."""
    data = message.encode('utf-8')
    padded = pad_message(data)

    h_state = list(H_INIT)

    # Process each 64-byte block
    for i in range(0, len(padded), 64):
        block = padded[i:i + 64]
        h_state = process_block(block, h_state, num_rounds)

    return ''.join(f'{val:08x}' for val in h_state)
