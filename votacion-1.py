import csv
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tkinter as tk

def buscar_usuario(dni):
    with open('basedatos.csv', mode='r') as archivo_csv:
        # Crea un objeto lector de CSV
        lector_csv = csv.reader(archivo_csv)
        for fila in lector_csv:
            if fila and fila[0]==dni:
                return fila
def verificar_clave(intento, key, salt):
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
        return False
    else:
        return True
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
def addto_csv(nuevo_usuario):
    # nueva_fila = ["Elena", 28, "Barranquilla"]
    # Abre el archivo CSV en modo "append" ('a')
    with open('basedatos.csv', mode='a', newline='') as archivo_csv:
        # Crea un objeto escritor de CSV
        escritor_csv = csv.writer(archivo_csv)
        # Escribe la nueva fila en el archivo CSV
        escritor_csv.writerow(nuevo_usuario)

def iniciar_sesion():
    dni = dni_entry.get()
    contrasena = contrasena_entry.get()
    # Agrega la lógica de inicio de sesión aquí.
    usuario=buscar_usuario(dni)
    if usuario!=None:
        con_by= bytes.fromhex(usuario[1])
        validez=verificar_clave(contrasena, usuario[1], usuario[2])
        if validez:
            print("entra")
        else:
            print("contraseña incorrecta")
    else:
        print("usuario no valido")
def registrar_usuario():
    nombre = nombre_entry.get()
    apellido = apellido_entry.get()
    fecha_nacimiento = fecha_nacimiento_entry.get()
    dni = dni_registro_entry.get()
    contrasena = contrasena_registro_entry.get()
    con_cifrada, salt= cifrar_clave(contrasena)
    con_cifrada_hex= con_cifrada.hex()
    n_usuario= [dni,con_cifrada_hex,salt,nombre,apellido,fecha_nacimiento]
    addto_csv(n_usuario)

def abrir_ventana_registro():
    ventana_registro = tk.Toplevel(ventana)
    ventana_registro.title("Registro")

    # Etiquetas y campos de entrada para el registro
    nombre_label = tk.Label(ventana_registro, text="Nombre:")
    nombre_entry = tk.Entry(ventana_registro)
    apellido_label = tk.Label(ventana_registro, text="Apellido:")
    apellido_entry = tk.Entry(ventana_registro)
    fecha_nacimiento_label = tk.Label(ventana_registro, text="Fecha de Nacimiento:")
    fecha_nacimiento_entry = tk.Entry(ventana_registro)
    dni_registro_label = tk.Label(ventana_registro, text="DNI:")
    dni_registro_entry = tk.Entry(ventana_registro)
    contrasena_registro_label = tk.Label(ventana_registro, text="Contraseña:")
    contrasena_registro_entry = tk.Entry(ventana_registro, show="*")

    # Botón para registrar
    registrar_button = tk.Button(ventana_registro, text="Registrarse")
    registrar_button.grid(row=8, column=0, columnspan=2)

    nombre_label.grid(row=0, column=0)
    nombre_entry.grid(row=0, column=1)
    apellido_label.grid(row=1, column=0)
    apellido_entry.grid(row=1, column=1)
    fecha_nacimiento_label.grid(row=2, column=0)
    fecha_nacimiento_entry.grid(row=2, column=1)
    dni_registro_label.grid(row=3, column=0)
    dni_registro_entry.grid(row=3, column=1)
    contrasena_registro_label.grid(row=4, column=0)
    contrasena_registro_entry.grid(row=4, column=1)

ventana = tk.Tk()
ventana.title("Aplicación de Inicio de Sesión")

dni_label = tk.Label(ventana, text="DNI:")
dni_entry = tk.Entry(ventana)
contrasena_label = tk.Label(ventana, text="Contraseña:")
contrasena_entry = tk.Entry(ventana, show="*")

iniciar_sesion_button = tk.Button(ventana, text="Iniciar Sesión", command=iniciar_sesion)
registrarse_button = tk.Button(ventana, text="Registrarse", command=abrir_ventana_registro)

dni_label.grid(row=0, column=0)
dni_entry.grid(row=0, column=1)
contrasena_label.grid(row=1, column=0)
contrasena_entry.grid(row=1, column=1)
iniciar_sesion_button.grid(row=2, column=0, columnspan=2)
registrarse_button.grid(row=3, column=0, columnspan=2)

ventana.mainloop()
