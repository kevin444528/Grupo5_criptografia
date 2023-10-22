import tkinter as tk
import pandas as pd
import csv
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AplicacionRegistro:
    def __init__(self, ventana):
        self.nombre_basedatos='basedatos.csv'
        self.nombre_basedatos_key='base_datos_key.csv'
        """nombre_col = ["dni", "con_cifrada", "salt", "nombre_encr", "nonce_nombre", "apellido_encr", "nonce_apellido",
                      "fecha_encr", "nonce_fecha", "voto", "nonce_voto"]"""
        self.base_panda=pd.read_csv("basedatos.csv")
        self.base_panda["voto"] = self.base_panda["voto"].astype(object)
        self.base_panda["nonce_voto"] = self.base_panda["nonce_voto"].astype(object)
        print(self.base_panda.dtypes)
        self.ventana = ventana
        self.ventana.title("Aplicación de Inicio de Sesión")
        self.dni_label = tk.Label(ventana, text="DNI:")
        self.dni_entry = tk.Entry(ventana)
        self.contrasena_label = tk.Label(ventana, text="Contraseña:")
        self.contrasena_entry = tk.Entry(ventana, show="*")
        self.mensaje_error = tk.Label(ventana, text="", fg="red")

        self.clave=None

        self.iniciar_sesion_button = tk.Button(ventana, text="Iniciar Sesión", command=self.iniciar_sesion)
        self.registrarse_button = tk.Button(ventana, text="Registrarse", command=self.abrir_ventana_registro)


        self.dni_label.grid(row=0, column=0)
        self.dni_entry.grid(row=0, column=1)
        self.contrasena_label.grid(row=1, column=0)
        self.contrasena_entry.grid(row=1, column=1)
        self.iniciar_sesion_button.grid(row=2, column=0, columnspan=2)
        self.registrarse_button.grid(row=3, column=0, columnspan=2)
        self.mensaje_error.grid(rows=5, column=0, columnspan=2)

    def iniciar_sesion(self):
        dni = self.dni_entry.get()
        contrasena = self.contrasena_entry.get()
        # Agrega la lógica de inicio de sesión aquí.
        usuario = self.buscar_usuario(self.nombre_basedatos,dni)
        if usuario is not None:
            con_by = bytes.fromhex(usuario[1])
            salt_by= bytes.fromhex(usuario[2])
            validez = self.verificar_clave(contrasena, con_by, salt_by)
            if validez:
                self.mostrar_ventana_votacion()
                self.clave=contrasena
                print("entra")
            else:
                self.mostrar_error("Contraseña incorrecta")
        else:
            self.mostrar_error("Usuario no válido")

    def mostrar_error(self, mensaje):
        self.mensaje_error.config(text=mensaje)

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
        usuario = self.buscar_usuario(self.nombre_basedatos,dni)
        if usuario is not None:
            self.dni_mensaje_error.config(text="Ya existe un usuario registrado con este DNI")
            return False
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
        boton_opcion1 = tk.Button(self.ventana_votacion, text="Opción 1", command=lambda: self.votar(1))
        boton_opcion2 = tk.Button(self.ventana_votacion, text="Opción 2", command=lambda:self.votar(2))
        boton_opcion3 = tk.Button(self.ventana_votacion, text="Opción 3", command=lambda: self.votar(3))
        boton_opcion4 = tk.Button(self.ventana_votacion, text="Opción 4", command=lambda: self.votar(4))

        verdatos.grid(row=1, column=1, columnspan=2)

        boton_opcion1.grid(row=3, column=1, columnspan = 2)
        boton_opcion2.grid(row=4, column=1, columnspan = 2)
        boton_opcion3.grid(row=5, column=1, columnspan = 2)
        boton_opcion4.grid(row=6, column=1, columnspan = 2)

    def votar(self,opcion):
        self.base_panda=pd.read_csv("basedatos.csv")
        voto= "Opcion: "+ str(opcion)
        usuario= self.base_panda.loc[self.base_panda["dni"]==self.dni_entry.get()]
        salt= bytes.fromhex(usuario["salt"].iloc[0])
        voto_cif, nonce_voto = self.encriptar(voto,salt)
        voto_cif_str = voto_cif.hex()
        nonce_voto_str = nonce_voto.hex()
        # Realizar las asignaciones
        print(usuario["dni"],voto_cif, nonce_voto)
        self.base_panda.loc[self.base_panda["dni"] == self.dni_entry.get(), "voto"] = voto_cif_str
        self.base_panda.loc[self.base_panda["dni"] == self.dni_entry.get(), "nonce_voto"] = nonce_voto_str
        self.base_panda.to_csv("basedatos.csv", index=False)
        #men= self.desencriptar(bytes.fromhex(usuario["nombre_cfr"].iloc[0]), bytes.fromhex(usuario["nonce_nombre"].iloc[0]),bytes.fromhex(usuario["salt"].iloc[0]))
        #print(men)

    def ver_datos(self):
        self.ventana_datos = tk.Toplevel(self.ventana)
        self.ventana_datos.title("Mis datos")
        titulo_label = tk.Label(self.ventana_datos, text="Datos", font=("bold", 14))
        titulo_label.pack()
        usuario = self.buscar_usuario(self.nombre_basedatos,self.dni_entry.get())
        nombre=self.desencriptar(bytes.fromhex(usuario[3]), bytes.fromhex(usuario[4]),bytes.fromhex(usuario[2]))
        #print(bytes.fromhex(usuario[3]), bytes.fromhex(usuario[4]),bytes.fromhex(usuario[2]),usuario[3],usuario[4],[2])
        apellido = self.desencriptar(bytes.fromhex(usuario[5]), bytes.fromhex(usuario[6]), bytes.fromhex(usuario[2]))
        fecha = self.desencriptar(bytes.fromhex(usuario[7]), bytes.fromhex(usuario[8]), bytes.fromhex(usuario[2]))
        if usuario[9] =="":
            voto = "aun no ha votado"
        else:
            voto=self.desencriptar(bytes.fromhex(usuario[9]), bytes.fromhex(usuario[10]), bytes.fromhex(usuario[2]))
        # para hacer esto de alguna forma hay que pasarle el dni a esta función
        self.nombre_label = tk.Label(self.ventana_datos, text=f"Nombre: {nombre}")
        self.apellido_label = tk.Label(self.ventana_datos, text=f"Apellido:{apellido}")
        self.fecha_label = tk.Label(self.ventana_datos, text=f"Fecha de nacimiento:{fecha}")
        self.voto_label = tk.Label(self.ventana_datos, text=f"Voto: {voto}")



        self.nombre_label.pack()
        self.apellido_label.pack()
        self.fecha_label.pack()
        self.voto_label.pack()


    def buscar_usuario(self, fichero,dni):
        with open(fichero, mode='r') as archivo_csv:
            lector_csv = csv.reader(archivo_csv)
            for fila in lector_csv:
                if fila and fila[0] == dni:
                    return fila
    def addto_csv(self,fichero,nuevo_usuario):
        with open(fichero, mode='a', newline='') as archivo_csv:
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
    def derivar_clave(self,salt):
        # derive
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        clave = self.clave
        clave_bytes = clave.encode('utf-8')
        key = kdf.derive(clave_bytes)
        return key
    def encriptar(self, data,salt):
        algoritmo = "AES"
        data_b = data.encode('utf-8')
        key= self.derivar_clave(salt)
        print("contraseña encrip: ",key)

        key_length = len(key)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        # nos devuelve el dato encriptado y autenticado
        ct = aesgcm.encrypt(nonce, data_b, None)
        # imprimimos mensaje de depuración:
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return ct, nonce

    def desencriptar(self, ct, nonce,salt):
        algoritmo = "AES"
        key = self.derivar_clave(salt)
        print("contraseña desencrip: ",key)
        key_length = len(key)
        aesgcm = AESGCM(key)
        dato = aesgcm.decrypt(nonce, ct, None)
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return dato.decode()

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
            self.clave=contrasena
            con_cifrada, salt = self.cifrar_clave(self.clave)
            # print(type(con_cifrada))
            con_cifrada_hex = con_cifrada.hex()
            salt_hex = salt.hex()
            # al registrar al usuario ciframos los datos de nombre, apellido y fecha de nacimiento usando el dni
            # guarda el dato encriptado y seguidamente el nonce
            nombre_encr, nonce_nombre = self.encriptar(nombre, salt)
            apellido_encr, nonce_apellido = self.encriptar(apellido, salt)
            fecha_encr, nonce_fecha = self.encriptar(fecha_nacimiento, salt)
            n_usuario = [dni, con_cifrada_hex, salt_hex, nombre_encr.hex(), nonce_nombre.hex(), apellido_encr.hex(), nonce_apellido.hex(), fecha_encr.hex(), nonce_fecha.hex(),"",""]
            self.addto_csv(self.nombre_basedatos,n_usuario)
            #print( nombre_encr, nonce_nombre,salt,salt_hex, nombre_encr.hex(), nonce_nombre.hex())

            self.ventana_registro.destroy()


# Crear una instancia de la aplicación y ejecutarla
ventana = tk.Tk()
app = AplicacionRegistro(ventana)
ventana.mainloop()
