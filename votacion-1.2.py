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
        #Nombre de la base de datos
        self.nombre_basedatos='basedatos.csv'
        self.base_panda=pd.read_csv(self.nombre_basedatos)
        #Interfaz de la venta de inicio sesion
        self.ventana = ventana
        self.ventana.title("Aplicación de Inicio de Sesión")
        self.dni_label = tk.Label(ventana, text="DNI:")
        self.dni_entry = tk.Entry(ventana)
        self.contrasena_label = tk.Label(ventana, text="Contraseña:")
        self.contrasena_entry = tk.Entry(ventana, show="*")
        self.mensaje_error = tk.Label(ventana, text="", fg="red")

        self.iniciar_sesion_button = tk.Button(ventana, text="Iniciar Sesión", command=self.iniciar_sesion)
        self.registrarse_button = tk.Button(ventana, text="Registrarse", command=self.abrir_ventana_registro)


        self.dni_label.grid(row=0, column=0)
        self.dni_entry.grid(row=0, column=1)
        self.contrasena_label.grid(row=1, column=0)
        self.contrasena_entry.grid(row=1, column=1)
        self.iniciar_sesion_button.grid(row=2, column=0, columnspan=2)
        self.registrarse_button.grid(row=3, column=0, columnspan=2)
        self.mensaje_error.grid(rows=5, column=0, columnspan=2)
        #variable temporal que guarda el valor de la contraseña del usuario
        self.clave = None

    def iniciar_sesion(self):
        """Comprobacion del DNI y la contraseña que se introduce"""
        #obtenemos el DNI
        dni = self.dni_entry.get()
        contrasena = self.contrasena_entry.get()
        usuario = self.buscar_usuario(self.nombre_basedatos,dni)
        #Comprueba que el usuario esta en la base de datos
        if usuario is not None:
            con_by = bytes.fromhex(usuario[1])
            salt_by= bytes.fromhex(usuario[2])
            #Comprueba la contraseña con el hash que tenemos guardado
            validez = self.verificar_clave(contrasena, con_by, salt_by)
            if validez:
                self.mostrar_ventana_principal()
                self.clave=contrasena
                self.mostrar_error("")
            else:
                self.mostrar_error("Contraseña incorrecta")
        else:
            self.mostrar_error("Usuario no válido")

    def mostrar_error(self, mensaje):
        """Adapata el mensaje de error de inicio de sesion"""
        self.mensaje_error.config(text=mensaje)
    def mostrar_error_registro(self,mensaje):
        pass
    def comprobar_fecha(self):
        """Comprobacion del formato fecha"""
        fecha = self.fecha_nacimiento_entry.get()
        if len(fecha) != 10 or fecha[2] != "/" or fecha[5] != "/":
            self.fecha_mensaje_error.config(text="La fecha de nacimiento debe tener el formato: XX/XX/XXXX")
            return False
        else:
            self.fecha_mensaje_error.config(text="")
            return True

    def comprobar_dni(self):
        """Comprobacion del formato DNI"""
        dni = self.dni_registro_entry.get()
        if len(dni) != 9 or dni[-1].isnumeric() or dni[-1] not in "TRWAGMYFPDXBNJZSQVHLCKE":
            self.dni_mensaje_error.config(text="DNI no válido: debe contener 8 dígitos y 1 letra")
            return False
        usuario = self.buscar_usuario(self.nombre_basedatos,dni)
        #Comprobamos que no exista un usuario con el mismo DNI
        if usuario is not None:
            self.dni_mensaje_error.config(text="Ya existe un usuario registrado con este DNI")
            return False
        self.dni_mensaje_error.config(text="")
        return True

    def comprobar_contrasena(self):
        """Comprobacion del formato de contraseña"""
        contr = self.contrasena_registro_entry.get()
        #Obliga que la contraseña tenga un minimo de longitud
        if len(contr) < 8:
            self.contrasena_mensaje_error.config(text="La contraseña debe tener al menos 8 caracteres")
            return False
        else:
            self.contrasena_mensaje_error.config(text="")
            return True

    def mostrar_ventana_principal(self):
        """Interfaz de la ventana principal de la aplicación. Se muestra después de iniciar sesion"""
        self.ventana_principal = tk.Toplevel()
        self.ventana_principal.title("Votación")
        verdatos = tk.Button(self.ventana_principal, text="Mis datos", command=self.ver_datos)
        # Llaman a la funcion votar pasandole como parametro la eleccion
        vervotos = tk.Button(self.ventana_principal, text="Votar", command=self.ver_votos)
        # self.vervotos_mensaje = tk.Label(self.ventana_principal, text="")
        verdatos.grid(row=1, column=2, columnspan=2, pady=(10, 10), padx=(10, 10))
        vervotos.grid(row=6, column=2, columnspan=2, pady=(10, 10), padx=(10, 10))
        # self.vervotos_mensaje.grid(row=7, column=2, columnspan=2)

    def ver_votos(self):
        """Interfaz de la ventana de votación"""
        self.ventana_votos = tk.Toplevel(self.ventana)
        self.ventana_votos.title("Votación")
        boton_opcion1 = tk.Button(self.ventana_votos, text="Opción 1", command=lambda: self.votar(1))
        boton_opcion2 = tk.Button(self.ventana_votos, text="Opción 2", command=lambda: self.votar(2))
        boton_opcion3 = tk.Button(self.ventana_votos, text="Opción 3", command=lambda: self.votar(3))
        boton_opcion4 = tk.Button(self.ventana_votos, text="Opción 4", command=lambda: self.votar(4))

        boton_opcion1.grid(row=3, column=1, columnspan=2)
        boton_opcion2.grid(row=4, column=1, columnspan=2)
        boton_opcion3.grid(row=5, column=1, columnspan=2)
        boton_opcion4.grid(row=6, column=1, columnspan=2)

    def votar(self,opcion):
        """Añade o actuliza el voto a la lista del usuario"""
        self.base_panda=pd.read_csv("basedatos.csv")
        voto= "Opcion: "+ str(opcion)
        #Buscamos el usuario en la base de datos
        usuario= self.base_panda.loc[self.base_panda["dni"]==self.dni_entry.get()]
        salt= bytes.fromhex(usuario["salt"].iloc[0])
        #Encripatmos el voto
        voto_cif, nonce_voto = self.encriptar(voto,salt)
        voto_cif_str = voto_cif.hex()
        nonce_voto_str = nonce_voto.hex()
        #Guardamos el voto cifrado con su nonce
        self.base_panda.loc[self.base_panda["dni"] == self.dni_entry.get(), "voto"] = voto_cif_str
        self.base_panda.loc[self.base_panda["dni"] == self.dni_entry.get(), "nonce_voto"] = nonce_voto_str
        #Añadimos las modificaciones al fichero
        self.base_panda.to_csv("basedatos.csv", index=False)
        self.ventana_votos.destroy()

    def ver_datos(self):
        """Interfaz de la ventana datos"""
        self.ventana_datos = tk.Toplevel(self.ventana)
        self.ventana_datos.title("Mis datos")
        titulo_label = tk.Label(self.ventana_datos, text="Datos", font=("bold", 14))
        titulo_label.pack()
        #Buscamos el usuario
        usuario = self.buscar_usuario(self.nombre_basedatos,self.dni_entry.get())
        nombre=self.desencriptar(bytes.fromhex(usuario[3]), bytes.fromhex(usuario[4]),bytes.fromhex(usuario[2]))
        apellido = self.desencriptar(bytes.fromhex(usuario[5]), bytes.fromhex(usuario[6]), bytes.fromhex(usuario[2]))
        fecha = self.desencriptar(bytes.fromhex(usuario[7]), bytes.fromhex(usuario[8]), bytes.fromhex(usuario[2]))
        #Comprueba si el usuario ha votado
        if usuario[9] =="":
            voto = "aun no ha votado"
        else:
            voto=self.desencriptar(bytes.fromhex(usuario[9]), bytes.fromhex(usuario[10]), bytes.fromhex(usuario[2]))
        # para hacer esto de alguna forma hay que pasarle el dni a esta función
        nombre_label = tk.Label(self.ventana_datos, text=f"Nombre: {nombre}")
        apellido_label = tk.Label(self.ventana_datos, text=f"Apellido:{apellido}")
        fecha_label = tk.Label(self.ventana_datos, text=f"Fecha de nacimiento:{fecha}")
        voto_label = tk.Label(self.ventana_datos, text=f"Voto: {voto}")


        nombre_label.pack()
        apellido_label.pack()
        fecha_label.pack()
        voto_label.pack()


    def buscar_usuario(self, fichero,dni):
        """Busca un usuario por su DNI en un csv"""
        with open(fichero, mode='r') as archivo_csv:
            lector_csv = csv.reader(archivo_csv)
            for fila in lector_csv:
                if fila and fila[0] == dni:
                    return fila
    def addto_csv(self,fichero,nuevo_usuario):
        """Añade una fila/usuario a un fichero csv """
        with open(fichero, mode='a', newline='') as archivo_csv:
            # Crea un objeto escritor de CSV
            escritor_csv = csv.writer(archivo_csv)
            # Escribe la nueva fila en el archivo CSV
            escritor_csv.writerow(nuevo_usuario)



    def verificar_clave(self, intento, key, salt):
        """Verifica una clave cifrada con Scrypt. Intento es la clave con la que se esta intentando
        entrar a la cuenta de usuario y key es la contraseña cifrada guardada"""

        algoritmo = "Scrypt"
        key_length = 32
        kdf = Scrypt(
            salt=salt,
            length=key_length,
            n=2**14,
            r=8,
            p=1,
        )
        #Usamos un try para que el mensaje de error en caso de no coincidir pare el programa
        try:
            #Comprobamos si la contraseña es correcta
            kdf.verify(intento.encode('utf-8'), key)
            print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        except cryptography.exceptions.InvalidKey as e:
            return False
        else:
            return True

    def cifrar_clave(self, clave):
        """Cifra una cadena de texto usando el algoritmo Scrypt"""
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
        #Transforma la cadena de texto en cadena de bit
        clave_bytes = clave.encode('utf-8')
        key = kdf.derive(clave_bytes)
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return key, salt
    def derivar_clave(self,salt):
        """Deriva la clave actual"""
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
        """Encripta datos con un salt pasado como parametro"""
        algoritmo = "AES"
        #Transformamos los datos en cadena de bits
        data_b = data.encode('utf-8')
        #Deriva la la llave que sera la contraseña del usuario actual
        key= self.derivar_clave(salt)

        key_length = len(key)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        # nos devuelve el dato encriptado y autenticado
        ct = aesgcm.encrypt(nonce, data_b, None)
        # imprimimos mensaje de depuración:
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return ct, nonce

    def desencriptar(self, ct, nonce, salt):
        """Desencripta datos con un determinado nonce y salt"""
        algoritmo = "AES"
        key = self.derivar_clave(salt)
        key_length = len(key)
        aesgcm = AESGCM(key)
        dato = aesgcm.decrypt(nonce, ct, None)
        print(f"Información sobre el cifrado: \nEl algoritmo usado para cifrar es {algoritmo} y la longitud de la clave es {key_length}")
        return dato.decode()

    def abrir_ventana_registro(self):
        """Interfaz de la ventana de registro de usuario"""
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

        self.volver_button = tk.Button(self.ventana_registro, text="Volver", command= lambda :self.ventana_registro.destroy())
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
        """Recibe los datos del usuario, realiza las comprabaciones y añade el nuevo usuario a la base de datos"""
        #Coge los valores
        nombre = self.nombre_entry.get()
        apellido = self.apellido_entry.get()
        fecha_nacimiento = self.fecha_nacimiento_entry.get()
        dni = self.dni_registro_entry.get()
        contrasena = self.contrasena_registro_entry.get()
        #Hace comprobacione
        if nombre != "" and apellido != "" and self.comprobar_fecha() and self.comprobar_dni() and self.comprobar_contrasena():
            #Asigna la contraseña de registro al atributo clave para poder encriptar los datos antes de almacenarlos
            self.clave=contrasena
            #Cifra la clave
            con_cifrada, salt = self.cifrar_clave(self.clave)

            con_cifrada_hex = con_cifrada.hex()
            salt_hex = salt.hex()
            # al registrar al usuario ciframos los datos de nombre, apellido y fecha de nacimiento usando el dni
            # guarda el dato encriptado  y seguidamente el nonce
            nombre_encr, nonce_nombre = self.encriptar(nombre, salt)
            apellido_encr, nonce_apellido = self.encriptar(apellido, salt)
            fecha_encr, nonce_fecha = self.encriptar(fecha_nacimiento, salt)
            #Lo guardamos en formato hexadecimal para que tenga una visibilidad mejor la base de datos
            n_usuario = [dni, con_cifrada_hex, salt_hex, nombre_encr.hex(), nonce_nombre.hex(), apellido_encr.hex(), nonce_apellido.hex(), fecha_encr.hex(), nonce_fecha.hex(),"",""]
            self.addto_csv(self.nombre_basedatos,n_usuario)
            self.ventana_registro.destroy()


# Crear una instancia de la aplicación y ejecutarla
ventana = tk.Tk()
app = AplicacionRegistro(ventana)
ventana.mainloop()
