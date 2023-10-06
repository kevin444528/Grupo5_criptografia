import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
data = input("Envía un mensaje: ")

aad = b"DNI"
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
ct = aesgcm.encrypt(nonce, b"data", aad)
voto = aesgcm.decrypt(nonce, ct, aad)
print(voto.decode())

