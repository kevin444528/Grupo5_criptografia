import csv
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



def addto_csv(nuevo_usuario):
    # nueva_fila = ["Elena", 28, "Barranquilla"]

    # Abre el archivo CSV en modo "append" ('a')
    with open('basedatos.csv', mode='a', newline='') as archivo_csv:
        # Crea un objeto escritor de CSV
        escritor_csv = csv.writer(archivo_csv)

        # Escribe la nueva fila en el archivo CSV
        escritor_csv.writerow(nuevo_usuario)

def buscar_usuario(dni):
    with open('basedatos.csv', mode='r') as archivo_csv:
        # Crea un objeto lector de CSV
        lector_csv = csv.reader(archivo_csv)
        for fila in lector_csv:
            if fila and fila[0]==dni:
                return fila

def read_csv(dato):
    with open('basedatos.csv', 'r') as archivo_csv:
        # Crea un objeto lector de CSV
        lector_csv = csv.reader(archivo_csv)

        # Itera a través de las filas del archivo CSV
        # creo que no sería for fila; sólo hay que mirar la columna de los DNI
        for fila in lector_csv:
            # fila es una lista de valores en la fila actual
            # nombre, apellidos, fecha de nacimiento, DNI, key = fila
            if dato:
                return True
            else:
                return False


def cifrar_clave(clave):
    salt = os.urandom(16)
    # derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    clave_bytes = clave.encode('utf-8')
    key = kdf.derive(clave_bytes)
    return key, salt


def descifrar_clave(intento, key, salt):
    # derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    try:
        kdf.verify(intento.encode('utf-8'), key)
        # Código que puede generar la excepción InvalidKey
    except cryptography.exceptions.InvalidKey as e:
        # Manejar la excepción InvalidKey y mostrar un mensaje personalizado
        print(f"Error: {e}")  # Imprimir un mensaje personalizado
    else:
        print("Contraseña valida")


# inicio
print("Bienvenid@ al Sistema Encriptado de Votación Electrónica, o también conocido como SEVE\n"
      "Para continuar, introduzca su DNI\n")

dni = input("DNI: ")
password = input("Contraseña: ")

if (buscar_usuario(dni)!=None):
    # no sé si se podría hacer if input(...) in archivo_csv
    # inicio sesión
    # de dónde sale key?
    # la contraseña se guarda cifrada en el csv (key) y con la key y la contraseña en sí se puede descrifrar (?)
    # leer key del csv en la fila del DNI que se ha introducido; pendiente de hacer
    descifrar_clave(password, read_csv(key), read_csv(salt))
else:
    if input("Ud. no está registrado en el censo electrónico. Pulse -Enter- para registrarse") == "\n":
        # registro del usuario
        # comprobar que funciona así
        nuevo_usuario = []
        """nuevo_usuario.append(input("Nombre: "))
        nuevo_usuario.append(input("Apellidos: "))
        nuevo_usuario.append(input("Fecha de nacimiento: "))"""
        nuevo_usuario.append(input("DNI: "))
        nuevo_usuario.append(cifrar_clave(input("Contraseña: ")))
        addto_csv(nuevo_usuario)
        print("Acaba de registrarse Ud. en el censo electrónico")
    else:
        print("Ha salido Ud. de la aplicación")

data = input("Introduzca su voto: ")
key = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
# cambiar a bytes el dni (aad) y el voto (data)
data_cifr = data.encode('utf-8')
dni_cifr = dni.encode('utf-8')
ct = aesgcm.encrypt(nonce, data_cifr, dni_cifr)
voto = aesgcm.decrypt(nonce, ct, dni_cifr)
print(voto.decode())
