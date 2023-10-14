import tkinter as tk
import csv
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

    def comprobar_fecha(self):
        fecha = self.fecha_nacimiento_entry.get()
        if len(fecha) != 10 or fecha[2] != "/" or fecha[5] != "/":
            self.fecha_mensaje_error.config(text="La fecha de nacimiento debe tener el formato: XX/XX/XXXX")
            return False
        else:
            self.fecha_mensaje_error.config(text="")
            return True

    def comprobar_dni(self):
        dni = self.dni_registro_entry.get()
        if len(dni) != 9 or dni[-1].isnumeric() or dni[-1] not in "TRWAGMYFPDXBNJZSQVHLCKE":
            self.dni_mensaje_error.config(text="DNI no válido: debe contener 8 dígitos y 1 letra")
            return False
        else:
            self.dni_mensaje_error.config(text="")
            return True

    def comprobar_contrasena(self):
        contr = self.contrasena_registro_entry.get()
        if len(contr) < 8:
            self.contrasena_mensaje_error.config(text="La contraseña debe tener al menos 8 caracteres")
            return False
        else:
            self.contrasena_mensaje_error.config(text="")
            return True

    def mostrar_ventana_votacion(self):
        self.ventana_votacion = tk.Toplevel(self.ventana)
        self.ventana_votacion.title("Votación")
        verdatos = tk.Button(self.ventana_votacion, text="Mis datos", command=self.ver_datos)
        # Agrega botones para votar en esta ventana
        boton_opcion1 = tk.Button(self.ventana_votacion, text="Opción 1", command=self.votar_opcion1)
        boton_opcion2 = tk.Button(self.ventana_votacion, text="Opción 2", command=self.votar_opcion2)
        boton_opcion3 = tk.Button(self.ventana_votacion, text="Opción 3", command=self.votar_opcion3)
        boton_opcion4 = tk.Button(self.ventana_votacion, text="Opción 4", command=self.votar_opcion4)

        verdatos.grid(row=1, column=1, columnspan=2)

        boton_opcion1.grid(row=3, column=1, columnspan = 2)
        boton_opcion2.grid(row=4, column=1, columnspan = 2)
        boton_opcion3.grid(row=5, column=1, columnspan = 2)
        boton_opcion4.grid(row=6, column=1, columnspan = 2)

    def votar_opcion1(self):
        # Agrega lógica de voto para la Opción 1 aquí
        print("Votaste por la Opción 1")
        self.ventana_votacion.destroy()

    def votar_opcion2(self):
        # Agrega lógica de voto para la Opción 2 aquí
        print("Votaste por la Opción 2")
        self.ventana_votacion.destroy()

    def votar_opcion3(self):
        # Agrega lógica de voto para la Opción 3 aquí
        print("Votaste por la Opción 3")
        self.ventana_votacion.destroy()

    def votar_opcion4(self):
        # Agrega lógica de voto para la Opción 4 aquí
        print("Votaste por la Opción 4")
        self.ventana_votacion.destroy()

    def ver_datos(self):
        self.ventana_datos = tk.Toplevel(self.ventana)
        self.ventana_datos.title("Registro")
        # para hacer esto de alguna forma hay que pasarle el dni a esta función
        self.nombre_label = tk.Label(self.ventana_datos, text="Nombre:")
        self.apellido_label = tk.Label(self.ventana_datos, text="Apellido:")
        self.fecha_label = tk.Label(self.ventana_datos, text="Fecha:")

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
        algoritmo = "Scrypt"
        key_length = 32
        kdf = Scrypt(
            salt=salt,
            length=key_length,
            n=2**14,
            r=8,
            p=1,
        )
        try:
            kdf.verify(intento.encode('utf-8'), key)
            print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        except cryptography.exceptions.InvalidKey as e:
            return False
        else:
            return True

    def cifrar_clave(self, clave):
        algoritmo = "Scrypt"
        salt = os.urandom(16)
        key_length = 32
        kdf = Scrypt(
            salt=salt,
            length=key_length,
            n=2**14,
            r=8,
            p=1,
        )
        clave_bytes = clave.encode('utf-8')
        key = kdf.derive(clave_bytes)
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return key, salt

    def encriptar(self, data, dni):
        algoritmo = "AES"
        data_b = data.encode('utf-8')
        # usamos el dni como el dato autenticado pero no encriptado, porque sabemos que pertence al usuario pero no está encriptado
        dni_b = dni.encode('utf-8')
        key_length = 128
        key = AESGCM.generate_key(bit_length=key_length)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        # nos devuelve el dato encriptado y autenticado
        ct = aesgcm.encrypt(nonce, data_b, dni_b)
        # imprimimos mensaje de depuración:
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return ct, nonce

    def desencriptar(self, ct, nonce, dni):
        algoritmo = "AES"
        dni_b = dni.encode('utf-8')
        key_length = 128
        key = AESGCM.generate_key(bit_length=key_length)
        aesgcm = AESGCM(key)
        dato = aesgcm.decrypt(nonce, ct, dni_b)
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return dato

    def abrir_ventana_registro(self):
        self.ventana_registro = tk.Toplevel(self.ventana)
        self.ventana_registro.title("Registro")

        self.nombre_label = tk.Label(self.ventana_registro, text="Nombre:")
        self.nombre_entry = tk.Entry(self.ventana_registro)
        self.apellido_label = tk.Label(self.ventana_registro, text="Apellido:")
        self.apellido_entry = tk.Entry(self.ventana_registro)
        self.fecha_nacimiento_label = tk.Label(self.ventana_registro, text="Fecha de Nacimiento:")
        self.fecha_mensaje_error = tk.Label(self.ventana_registro, text="", fg="red")
        self.fecha_nacimiento_entry = tk.Entry(self.ventana_registro)
        self.dni_registro_label = tk.Label(self.ventana_registro, text="DNI:")
        self.dni_mensaje_error = tk.Label(self.ventana_registro, text="", fg="red")
        self.dni_registro_entry = tk.Entry(self.ventana_registro)
        self.contrasena_registro_label = tk.Label(self.ventana_registro, text="Contraseña:")
        self.contrasena_mensaje_error = tk.Label(self.ventana_registro, text="", fg="red")
        self.contrasena_registro_entry = tk.Entry(self.ventana_registro, show="*")

        self.registrar_button = tk.Button(self.ventana_registro, text="Registrarse", command=self.registrar_usuario)
        self.registrar_button.grid(row=10, column=0, columnspan=2)

        self.volver_button = tk.Button(self.ventana_registro, text="Volver", command=self.ventana)
        self.volver_button.grid(row=11, column=0, columnspan=2)

        self.nombre_label.grid(row=0, column=0)
        self.nombre_entry.grid(row=0, column=1)
        self.apellido_label.grid(row=1, column=0)
        self.apellido_entry.grid(row=1, column=1)
        self.fecha_nacimiento_label.grid(row=2, column=0)
        self.fecha_nacimiento_entry.grid(row=2, column=1)
        self.fecha_mensaje_error.grid(row=5, column=0, columnspan=2)
        self.dni_registro_label.grid(row=3, column=0)
        self.dni_registro_entry.grid(row=3, column=1)
        self.dni_mensaje_error.grid(row=6, column=0, columnspan=2)
        self.contrasena_registro_label.grid(row=4, column=0)
        self.contrasena_registro_entry.grid(row=4, column=1)
        self.contrasena_mensaje_error.grid(row=7, column=0, columnspan=2)

    def registrar_usuario(self):
        nombre = self.nombre_entry.get()
        apellido = self.apellido_entry.get()
        fecha_nacimiento = self.fecha_nacimiento_entry.get()
        dni = self.dni_registro_entry.get()
        contrasena = self.contrasena_registro_entry.get()
        if nombre != "" and apellido != "" and self.comprobar_fecha() and self.comprobar_dni() and self.comprobar_contrasena():
            con_cifrada, salt = self.cifrar_clave(contrasena)
            # print(type(con_cifrada))
            con_cifrada_hex = con_cifrada.hex()
            salt_hex = salt.hex()
            # al registrar al usuario ciframos los datos de nombre, apellido y fecha de nacimiento usando el dni
            # guarda el dato encriptado y seguidamente el nonce
            nombre_encr, nonce_nombre = self.encriptar(nombre, dni)
            apellido_encr, nonce_apellido = self.encriptar(apellido, dni)
            fecha_encr, nonce_fecha = self.encriptar(fecha_nacimiento, dni)
            n_usuario = [dni, con_cifrada_hex, salt_hex, nombre_encr.hex(), nonce_nombre.hex(), apellido_encr.hex(), nonce_apellido.hex(), fecha_encr.hex(), nonce_fecha.hex()]
            self.addto_csv(n_usuario)
            self.ventana_registro.destroy()


# Crear una instancia de la aplicación y ejecutarla
ventana = tk.Tk()
app = AplicacionRegistro(ventana)
ventana.mainloop()
