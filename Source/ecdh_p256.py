# ecdh_p256.py
# ECDH P-256 mínimo para MicroPython
# Shared secret = coordenada X de d * Q

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = (P - 3) % P
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

INF = None


def inv_mod(k, p=P):
    if k == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    return pow(k, p - 2, p)


def is_on_curve(point):
    if point is INF:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P == 0:
        return INF

    if p1 == p2:
        if y1 == 0:
            return INF
        lam = ((3 * x1 * x1 + A) * inv_mod(2 * y1)) % P
    else:
        lam = ((y2 - y1) * inv_mod((x2 - x1) % P)) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    if k % N == 0 or point is INF:
        return INF
    if k < 0:
        x, y = point
        return scalar_mult(-k, (x, (-y) % P))

    result = INF
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def decode_uncompressed_pub(pub_bytes):
    if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
        raise ValueError("Clave pública ECDH no válida: se esperaba formato uncompressed de 65 bytes")
    x = int.from_bytes(pub_bytes[1:33], "big")
    y = int.from_bytes(pub_bytes[33:65], "big")
    point = (x, y)
    if not is_on_curve(point):
        raise ValueError("La clave pública ECDH no está en la curva P-256")
    return point


def rand_scalar(randfunc):
    while True:
        d = int.from_bytes(randfunc(32), "big") % N
        if 1 <= d < N:
            return d


def ecdh_shared_secret(priv_d, peer_pub_uncompressed):
    peer_point = decode_uncompressed_pub(peer_pub_uncompressed)
    shared = scalar_mult(priv_d, peer_point)
    if shared is INF:
        raise ValueError("Shared secret inválido")
    x, _ = shared
    return x.to_bytes(32, "big")
