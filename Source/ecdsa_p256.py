# ecdsa_p256.py (MicroPython) - firma ECDSA P-256, salida r||s (64 bytes)
import uhashlib
from uos import urandom

p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a  = p - 3
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def sha256(bts: bytes) -> bytes:
    h = uhashlib.sha256()
    h.update(bts)
    return h.digest()

def inv_mod(k, mod):
    return pow(k, mod - 2, mod)

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P != Q:
        lam = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
    else:
        lam = ((3 * x1 * x1 + a) * inv_mod((2 * y1) % p, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    R = None
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

def ecdsa_sign(message: bytes, priv_d: int) -> bytes:
    z = int.from_bytes(sha256(message), "big") % n
    while True:
        k = (int.from_bytes(urandom(32), "big") % (n - 1)) + 1
        x1, _ = scalar_mult(k, (Gx, Gy))
        r = x1 % n
        if r == 0:
            continue
        s = (inv_mod(k, n) * (z + r * priv_d)) % n
        if s == 0:
            continue
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        
def public_key_xy_from_priv(priv_d: int):
    return scalar_mult(priv_d, (Gx, Gy))

def public_key_uncompressed_from_priv(priv_d: int) -> bytes:
    """
    Formato SEC1 sin comprimir: 0x04 || X(32) || Y(32)
    """
    x, y = public_key_xy_from_priv(priv_d)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
