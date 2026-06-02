from pathlib import Path
from Crypto.PublicKey import ECC

key = ECC.generate(curve="P-256")
pub = key.public_key()

Path("backend_ecdh_private.pem").write_text(
    key.export_key(format="PEM"),
    encoding="utf-8"
)

pub_uncompressed = (
    b"\x04"
    + int(pub.pointQ.x).to_bytes(32, "big")
    + int(pub.pointQ.y).to_bytes(32, "big")
)

print("BACKEND_ECDH_PUB_HEX =")
print(pub_uncompressed.hex())
print("\nSe ha guardado backend_ecdh_private.pem")
