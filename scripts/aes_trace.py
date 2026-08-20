# Trace AES-128 rounds for cross-checking the Rust port.
def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def ginv(a):
    for i in range(256):
        if gmul(a, i) == 1:
            return i
    return 0


def sbox(x):
    if x == 0:
        y = 0
    else:
        y = ginv(x)
    r = 0
    for i in range(8):
        b = (y >> i) & 1
        b ^= (y >> ((i + 4) % 8)) & 1
        b ^= (y >> ((i + 5) % 8)) & 1
        b ^= (y >> ((i + 6) % 8)) & 1
        b ^= (y >> ((i + 7) % 8)) & 1
        r |= ((b ^ ((0x63 >> i) & 1)) << i)
    return r


S = [sbox(i) for i in range(256)]


def xtime(b):
    return ((b << 1) & 0xFF) ^ (0x1B if b & 0x80 else 0)


def shift_rows(s):
    o = [0] * 16
    o[0] = s[0]; o[1] = s[5]; o[2] = s[10]; o[3] = s[15]
    o[4] = s[4]; o[5] = s[9]; o[6] = s[14]; o[7] = s[3]
    o[8] = s[8]; o[9] = s[13]; o[10] = s[2]; o[11] = s[7]
    o[12] = s[12]; o[13] = s[1]; o[14] = s[6]; o[15] = s[11]
    return o


def mix_cols(s):
    o = [0] * 16
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
        o[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        o[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        o[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        o[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
    return o


def expand(key, nk, nr):
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(nk)]
    rcon = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54]
    for i in range(nk, nk * (nr + 1)):
        t = w[i - 1][:]
        if i % nk == 0:
            t = [S[t[1]], S[t[2]], S[t[3]], S[t[0]]]
            t[0] ^= rcon[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [S[t[0]], S[t[1]], S[t[2]], S[t[3]]]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w


def fmt(state):
    return " ".join("%02x" % b for b in state)


key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]
pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
w = expand(key, 4, 10)
state = pt[:]
for i in range(16):
    state[i] ^= w[i // 4][i % 4]
print("r0:", fmt(state))
for rnd in range(1, 10):
    state = [S[b] for b in state]
    state = shift_rows(state)
    state = mix_cols(state)
    for i in range(16):
        state[i] ^= w[rnd * 4 + i // 4][i % 4]
    print("r%d:" % rnd, fmt(state))
state = [S[b] for b in state]
state = shift_rows(state)
for i in range(16):
    state[i] ^= w[40 + i // 4][i % 4]
print("rfinal:", fmt(state))
