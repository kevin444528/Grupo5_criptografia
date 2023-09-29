import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography.exceptions
# Salts should be randomly generated
salt = os.urandom(16)
# derive
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
clave= input("Inserta tu clave:\n")
clave_bytes=clave.encode('utf-8')
key = kdf.derive(clave_bytes)
# verify
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
)
#kdf.verify(b"my great password", key)
"""print(clave_bytes, key)
if kdf.verify(b"hola", key):
    print("La contraseña es válida.")
else:
    print("La contraseña no es válida.")"""



try:
    kdf.verify(b"my great password", key)
    # Código que puede generar la excepción InvalidKey

except cryptography.exceptions.InvalidKey as e:
    # Manejar la excepción InvalidKey y mostrar un mensaje personalizado
    print(f"Error: {e}")  # Imprimir un mensaje personalizado
