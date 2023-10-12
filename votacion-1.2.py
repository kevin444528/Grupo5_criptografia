import tkinter as tk
import csv
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import cryptography.exceptions

class AplicacionRegistro:
    def __init__(self, ventana):
        self.ventana = ventana
        self.ventana.title("Aplicación de Inicio de Sesión")

        self.dni_label = tk.Label(ventana, text="DNI:")
        self.dni_entry = tk.Entry(ventana)
        self.contrasena_label = tk.Label(ventana, text="Contraseña:")
        self.contrasena_entry = tk.Entry(ventana, show="*")

        self.iniciar_sesion_button = tk.Button(ventana, text="Iniciar Sesión", command=self.iniciar_sesion)
        self.registrarse_button = tk.Button(ventana, text="Registrarse", command=self.abrir_ventana_registro)

        self.dni_label.grid(row=0, column=0)
        self.dni_entry.grid(row=0, column=1)
        self.contrasena_label.grid(row=1, column=0)
        self.contrasena_entry.grid(row=1, column=1)
        self.iniciar_sesion_button.grid(row=2, column=0, columnspan=2)
        self.registrarse_button.grid(row=3, column=0, columnspan=2)

    def iniciar_sesion(self):
        dni = self.dni_entry.get()
        contrasena = self.contrasena_entry.get()
        # Agrega la lógica de inicio de sesión aquí.
        usuario = self.buscar_usuario(dni)
        if usuario is not None:
            con_by = bytes.fromhex(usuario[1])
            salt_by= bytes.fromhex(usuario[2])
            validez = self.verificar_clave(contrasena, con_by, salt_by)
            if validez:
                self.mostrar_ventana_votacion()
                print("entra")
            else:
                print("contraseña incorrecta")
        else:
            print("usuario no válido")
    def mostrar_ventana_votacion(self):
        ventana_votacion = tk.Toplevel(self.ventana)
        ventana_votacion.title("Votación")

        # Agrega botones para votar en esta ventana
        boton_opcion1 = tk.Button(ventana_votacion, text="Opción 1", command=self.votar_opcion1)
        boton_opcion2 = tk.Button(ventana_votacion, text="Opción 2", command=self.votar_opcion2)
        boton_opcion3 = tk.Button(ventana_votacion, text="Opción 3", command=self.votar_opcion3)
        boton_opcion4 = tk.Button(ventana_votacion, text="Opción 4", command=self.votar_opcion4)

        boton_opcion1.pack()
        boton_opcion2.pack()
        boton_opcion3.pack()
        boton_opcion4.pack()

    def votar_opcion1(self):
        # Agrega lógica de voto para la Opción 1 aquí
        print("Votaste por la Opción 1")

    def votar_opcion2(self):
        # Agrega lógica de voto para la Opción 2 aquí
        print("Votaste por la Opción 2")

    def votar_opcion3(self):
        # Agrega lógica de voto para la Opción 3 aquí
        print("Votaste por la Opción 3")

    def votar_opcion4(self):
        # Agrega lógica de voto para la Opción 4 aquí
        print("Votaste por la Opción 4")
    def buscar_usuario(self, dni):
        with open('basedatos.csv', mode='r') as archivo_csv:
            lector_csv = csv.reader(archivo_csv)
            for fila in lector_csv:
                if fila and fila[0] == dni:
                    return fila
    def addto_csv(self,nuevo_usuario):
    # nueva_fila = ["Elena", 28, "Barranquilla"]
    # Abre el archivo CSV en modo "append" ('a')
        with open('basedatos.csv', mode='a', newline='') as archivo_csv:
            # Crea un objeto escritor de CSV
            escritor_csv = csv.writer(archivo_csv)
            # Escribe la nueva fila en el archivo CSV
            escritor_csv.writerow(nuevo_usuario)
    def verificar_clave(self, intento, key, salt):
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
    def cifrar_clave(self, clave):
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

    def abrir_ventana_registro(self):
        ventana_registro = tk.Toplevel(self.ventana)
        ventana_registro.title("Registro")

        self.nombre_label = tk.Label(ventana_registro, text="Nombre:")
        self.nombre_entry = tk.Entry(ventana_registro)
        self.apellido_label = tk.Label(ventana_registro, text="Apellido:")
        self.apellido_entry = tk.Entry(ventana_registro)
        self.fecha_nacimiento_label = tk.Label(ventana_registro, text="Fecha de Nacimiento:")
        self.fecha_nacimiento_entry = tk.Entry(ventana_registro)
        self.dni_registro_label = tk.Label(ventana_registro, text="DNI:")
        self.dni_registro_entry = tk.Entry(ventana_registro)
        self.contrasena_registro_label = tk.Label(ventana_registro, text="Contraseña:")
        self.contrasena_registro_entry = tk.Entry(ventana_registro, show="*")

        self.registrar_button = tk.Button(ventana_registro, text="Registrarse", command=self.registrar_usuario)
        self.registrar_button.grid(row=8, column=0, columnspan=2)

        self.nombre_label.grid(row=0, column=0)
        self.nombre_entry.grid(row=0, column=1)
        self.apellido_label.grid(row=1, column=0)
        self.apellido_entry.grid(row=1, column=1)
        self.fecha_nacimiento_label.grid(row=2, column=0)
        self.fecha_nacimiento_entry.grid(row=2, column=1)
        self.dni_registro_label.grid(row=3, column=0)
        self.dni_registro_entry.grid(row=3, column=1)
        self.contrasena_registro_label.grid(row=4, column=0)
        self.contrasena_registro_entry.grid(row=4, column=1)

    def registrar_usuario(self):
        nombre = self.nombre_entry.get()
        apellido = self.apellido_entry.get()
        fecha_nacimiento = self.fecha_nacimiento_entry.get()
        dni = self.dni_registro_entry.get()
        contrasena = self.contrasena_registro_entry.get()
        con_cifrada, salt= self.cifrar_clave(contrasena)
        con_cifrada_hex= con_cifrada.hex()
        salt_hex= salt.hex()
        n_usuario= [dni,con_cifrada_hex,salt_hex,nombre,apellido,fecha_nacimiento]
        self.addto_csv(n_usuario)

# Crear una instancia de la aplicación y ejecutarla
ventana = tk.Tk()
app = AplicacionRegistro(ventana)
ventana.mainloop()
