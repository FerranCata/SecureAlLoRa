from Crypto.PublicKey import ECC

PRIV_D = 1234  # pon aquí la privada REAL que usa ahora el Source

key = ECC.construct(curve="P-256", d=PRIV_D)
pub = key.public_key()

print(pub.export_key(format="PEM"))
