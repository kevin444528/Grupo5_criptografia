import tkinter as tk
import pandas as pd
import csv
import os
import subprocess
import shutil
import glob
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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
        dni = self.dni_entry.get()
        usuario= self.base_panda.loc[self.base_panda["dni"]==dni]
        salt = bytes.fromhex(usuario["salt"].iloc[0])
        #Encripatmos el voto simétricamente con AES
        voto_cif, nonce_voto = self.encriptar(voto,salt)
        voto_cif_str = voto_cif.hex()
        nonce_voto_str = nonce_voto.hex()
        #encriptamos el voto asimétricamente con RSA
        voto_cifr_firm = self.firmar(voto, dni)
        public_key = self.crear_clave_publica()
        voto_cif_asi = self.cifrar_asi(voto, )
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
        if usuario[9] == "":
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

    def firmar(self, voto, dni):
        """Función para firmar con la clave privada"""
        # La clave privada se encuentra en un fichero .pem -> la buscamos (key loading)
        # arreglar el "path to key" y buscar el fichero por dni del usuario
        # password sería la clave privada del maestro??? habría que pasarla en bytes
        with open("path/to/key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        # generamos la clave pública a partir de la contraseña de (?)
        public_key = self.crear_clave_publica(private_key)
        # ciframos asimétricamente el voto con la clave pública
        voto_cifrado = self.cifrar_asi(voto, public_key)
        # el voto cifrado se firma con la clave privada
        voto_cifr_firm = private_key.sign(
            voto_cifrado,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return voto_cifr_firm

    def cifrar_asi(self, voto, public_key):
        """Función que cifra asimetricamente el voto con la clave pública"""
        voto_cifrado = public_key.encrypt(
            voto,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return voto_cifrado

    def descifrar_asi(self, voto_cifrado, public_key):
        """Función que recibe un voto cifrado y lo descifra utilizando la clave pública"""
        pass

    def ver_firmar(self, voto_cifr_firm, private_key):
        """Función que recibe un voto cifrado y firmado y comprueba la firma, devolviendo únicamente el voto cifrado"""
        voto_cifrado = private_key.decrypt(
            voto_cifr_firm,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        return voto_cifrado

    def crear_clave_publica(self, key):
        """Función que genera una clave pública y otra privada para la firma de cada usuario"""
        public_key = key.public_key()
        return public_key

    def crear_clave_privada(self,dni):
        """Función que genera la clave privada"""
        #Generamos la clave privada aleatoria para un usuario
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        nombre_archivo = f"{dni}.pem"
        directorio = "Usuarios"
        nombre_dir = f"{dni}"
        ruta_usuarios = os.path.join(os.getcwd(), directorio, nombre_dir)
        ruta_completa = os.path.join(ruta_usuarios, nombre_archivo)
        #La almacenamos en un fichero .pem para cada usuario. El nombre del archivo es <dni>.pem
        # hay tres tipos -> decidir cuál vamos a usar; este es el primero
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
        )
        with open(ruta_completa, 'wb') as archivo_nuevo:
            archivo_nuevo.write(pem)
            print(f"Clave privada guardada en el nuevo archivo '{ruta_completa}'.")
        pem.splitlines()[0]
        b'-----BEGIN ENCRYPTED PRIVATE KEY-----'

        return private_key
    def crear_directorio(self,dni):
        nombre_dir=f"{dni}"
        directorio = "Usuarios"
        ruta_completa = os.path.abspath(os.path.join(directorio, nombre_dir))
        os.mkdir(ruta_completa)

    def generar_solicitud_certificado(self,dni):
        nombre_archivo = f"{dni}.pem"
        directorio = "Usuarios"
        nombre_dir = f"{dni}"
        ruta_usuarios = os.path.join(os.getcwd(), directorio, nombre_dir)
        archivo_clave_privada=os.path.join(ruta_usuarios, nombre_archivo)
        nombre_solicitud=f"{dni}req.pem"
        archivo_solicitud=os.path.join(ruta_usuarios, nombre_solicitud)
        with open(archivo_clave_privada, "rb") as f:
            loaded_private_key = serialization.load_pem_private_key(
                f.read(),
                password=b"mypassword",  # Aquí puedes proporcionar la contraseña si la clave está cifrada
                backend=default_backend()
            )
        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"{dni}"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{dni}.com"),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(f"{dni}.com"),
                x509.DNSName(f"www.{dni}.com"),
                x509.DNSName(f"subdomain.{dni}.com"),
            ]),
            critical=False,
            # Sign the CSR with our private key.
        ).sign(loaded_private_key, hashes.SHA256())
        # Write our CSR out to disk.
        with open(archivo_solicitud, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        ruta_solicitud= os.path.join(os.getcwd(), "PKI", "AC1","solicitudes",nombre_solicitud)
        with open(ruta_solicitud, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

    def generar_certificado(self,dni):
        nombre_solicitud = f"{dni}req.pem"
        ruta_solicitud= os.path.join(os.getcwd(), "PKI", "AC1","solicitudes",nombre_solicitud)
        configuracion_openssl= os.path.join(os.getcwd(), "PKI", "openSSL", "openssl_AC1.cnf")
        try:
            # Construir el comando 'openssl ca'
            comando = f"openssl ca -in {ruta_solicitud} -notext -config {configuracion_openssl}"
            # Ejecutar el comando en el sistema operativo
            resultado = subprocess.run(
                comando,
                shell=True,
                input="marinakevin2023\ny\ny\n",
                text=True,
                capture_output=True,
                check=True
            )
            # Imprimir la salida y el error
            print("Salida del comando:")
            print(resultado.stdout)

            if resultado.stderr:
                # Decodificar la salida de error si es bytes
                error_message = resultado.stderr.decode() if isinstance(resultado.stderr, bytes) else resultado.stderr
                print("Error del comando:")
                print(error_message)

            print("Ejecución de 'openssl ca' completada correctamente.")
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando 'openssl ca': {e}")
            print(f"Salida del comando: {e.stderr if e.stderr else 'No hay error'}")

    def copiar_ultimo_certificado(self,dni):
        nombre_dir = f"{dni}"
        directorio_origen = os.path.join(os.getcwd(), "PKI", "AC1", "nuevoscerts")
        directorio_destino = os.path.join(os.getcwd(),"Usuarios",nombre_dir)
        # Obtener la lista de archivos que coinciden con el patrón "*.pem"
        archivos_pem = glob.glob(os.path.join(directorio_origen, '*.pem'))
        if not archivos_pem:
            print("No hay archivos PEM en el directorio de origen.")
            return
        # Ordenar la lista de archivos por fecha de modificación descendente
        archivos_pem.sort(key=os.path.getmtime, reverse=True)
        # Tomar el archivo más reciente
        ultimo_certificado = archivos_pem[0]

        # Obtener el nombre del archivo sin la ruta
        nuevo_nombre= f"{dni}cert.pem"

        # Construir la ruta de destino
        ruta_destino = os.path.join(directorio_destino, nuevo_nombre)

        # Copiar el archivo al directorio de destino
        shutil.copy(ultimo_certificado, ruta_destino)
        print(f"Certificado copiado a {ruta_destino}")


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
        # se generan automáticamente las claves pública y privada
        # la segunda se guardará en un fichero .pem, pero esto se hace al generarse la clave en sí
        # TODO: la primera se guardará en claves-publicas.csv
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
            self.crear_directorio(dni)
            private_key = self.crear_clave_privada(dni)
            self.generar_solicitud_certificado(dni)
            self.generar_certificado(dni)
            self.copiar_ultimo_certificado(dni)
            self.ventana_registro.destroy()


# Crear una instancia de la aplicación y ejecutarla
ventana = tk.Tk()
app = AplicacionRegistro(ventana)
ventana.mainloop()
