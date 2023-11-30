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
from cryptography.hazmat.backends import openssl
from cryptography.x509 import load_pem_x509_certificate
from tkinter import ttk


class AplicacionRegistro:
    def __init__(self, ventana):
        #Nombre de la base de datos
        self.nombre_basedatos='basedatos.csv'
        self.base_panda=pd.read_csv(self.nombre_basedatos)
        #Interfaz de la venta de inicio sesion
        self.ventana= ventana
        self.ventana_password_autoridad()

        #variable temporal que guarda el valor de la contraseña del usuario
        self.clave = None
        self.clave_autoridad=None
    def ventana_password_autoridad(self):
        self.ventana.withdraw()
        self.ventana_pass = tk.Toplevel(self.ventana)
        self.ventana_pass.title("Contraseña autoridad")
        contrasena_label = tk.Label(self.ventana_pass, text="Contraseña AC1:")
        contrasena_entry = tk.Entry(self.ventana_pass, show="*")
        mensaje_error = tk.Label(self.ventana_pass, text="", fg="red")
        iniciar_app_button = tk.Button(self.ventana_pass, text="Enviar", command=lambda: self.verificar_pass_AC1(contrasena_entry, mensaje_error))
        contrasena_label.grid(row=1, column=0)
        contrasena_entry.grid(row=1, column=1)
        iniciar_app_button.grid(row=2, column=0, columnspan=2)
        mensaje_error.grid(rows=5, column=0, columnspan=2)
    def verificar_pass_AC1(self, contrasena_entry,mensaje_error):
        if self.is_valid_password(contrasena_entry.get()):
            mensaje_error.config(text="")
            self.clave_autoridad= contrasena_entry.get()
            self.ventana_pass.destroy()
            self.ventana.deiconify()
            self.ventana_inicio_sesion()
        else:
            mensaje_error.config(text="Contraseña incorrecta")

    def ventana_inicio_sesion(self):
        self.ventana.title("Aplicación de Inicio de Sesión")
        self.dni_label = tk.Label(self.ventana, text="DNI:")
        self.dni_entry = tk.Entry(self.ventana)
        self.contrasena_label = tk.Label(self.ventana, text="Contraseña:")
        self.contrasena_entry = tk.Entry(self.ventana, show="*")
        self.mensaje_error = tk.Label(self.ventana, text="", fg="red")

        self.iniciar_sesion_button = tk.Button(self.ventana, text="Iniciar Sesión", command=self.iniciar_sesion)
        self.registrarse_button = tk.Button(self.ventana, text="Registrarse", command=self.abrir_ventana_registro)

        self.dni_label.grid(row=0, column=0)
        self.dni_entry.grid(row=0, column=1)
        self.contrasena_label.grid(row=1, column=0)
        self.contrasena_entry.grid(row=1, column=1)
        self.iniciar_sesion_button.grid(row=2, column=0, columnspan=2)
        self.registrarse_button.grid(row=3, column=0, columnspan=2)
        self.mensaje_error.grid(rows=5, column=0, columnspan=2)

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
                self.clave = contrasena
                if dni!="00000000A":
                    self.mostrar_ventana_principal()
                    self.mostrar_error("")
                else:
                    self.mostrar_ventana_superuser()
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

    def mostrar_ventana_superuser(self):
        self.ventana_sup= tk.Toplevel(self.ventana)
        self.ventana_sup.title("Ver votos")
        base_votos= pd.read_csv("votos-usuarios.csv")
        self.tree= ttk.Treeview(self.ventana_sup)
        columna_mostrar= "dni"
        # Configurar columnas
        columnas_mostrar = ["dni", "voto"]  # Agrega "voto" a las columnas a mostrar
        self.tree["columns"] = tuple(columnas_mostrar)

        # Configurar encabezados y columnas
        for columna in columnas_mostrar:
            self.tree.heading("#0", text="", anchor=tk.CENTER)
            self.tree.column("#0", width=0, stretch=tk.NO)
            self.tree.heading(columna, text=columna)
            self.tree.column(columna, anchor=tk.CENTER)


        for index, row in base_votos.iterrows():
            #Verificamos el certificado del usuario y el voto firmado
            if (self.verificar_certificado(row["dni"]) and self.ver_firmar(row["dni"])):
                voto_bytes = self.descifrar_asi(bytes.fromhex(row["voto_cif_asi"]))
                voto = voto_bytes.decode()
                self.tree.insert("", index, values=(row["dni"],voto))
            else:
                self.tree.insert("", index, values=(row["dni"], "voto no coincide con la firma"))

        self.tree.pack(pady=10)



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
        base_votos=pd.read_csv("votos-usuarios.csv")
        voto= "Opcion: "+ str(opcion)
        #Buscamos el usuario en la base de datos
        dni = self.dni_entry.get()
        usuario= self.base_panda.loc[self.base_panda["dni"]==dni]
        salt = bytes.fromhex(usuario["salt"].iloc[0])
        #Encripatmos el voto simétricamente con AES
        voto_cif, nonce_voto = self.encriptar(voto,salt)
        voto_cif_str = voto_cif.hex()
        nonce_voto_str = nonce_voto.hex()
        #encriptamos el voto asimétricamente con RSA y firmamos
        voto_cif_asi = self.cifrar_asi(voto)
        voto_cif_asi_firmado= self.firmar(voto_cif_asi,dni)
        #Guardamos el voto cifrado con su nonce
        self.base_panda.loc[self.base_panda["dni"] == self.dni_entry.get(), "voto"] = voto_cif_str
        self.base_panda.loc[self.base_panda["dni"] == self.dni_entry.get(), "nonce_voto"] = nonce_voto_str
        #Guardamos voto asimetrico junto con su version firmada
        usu=base_votos.loc[base_votos["dni"]==dni]
        if not usu.empty:
            # Aquí realizas alguna acción si se encontró el usuario
            base_votos.loc[base_votos["dni"]==dni,"voto_cif_asi"]= voto_cif_asi.hex()
            base_votos.loc[base_votos["dni"] == dni, "voto_cif_asi_fir"] = voto_cif_asi_firmado.hex()
            base_votos.to_csv("votos-usuarios.csv", index=False)
        else:
            # Aquí realizas alguna acción si el usuario no fue encontrado
            usu_voto_nuevo=[dni,voto_cif_asi.hex(),voto_cif_asi_firmado.hex()]
            self.addto_csv("votos-usuarios.csv",usu_voto_nuevo)
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

    def firmar(self, voto_cifrado, dni):
        """Función para firmar con la clave privada"""
        # La clave privada se encuentra en un fichero .pem -> la buscamos (key loading)
        con_path = os.path.join(os.getcwd(), "Usuarios", f"{dni}", f"{dni}.pem")
        with open(con_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=self.clave.encode('utf-8'),
                backend=default_backend()
            )

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

    def cifrar_asi(self, voto):
        """Función que cifra asimetricamente el voto con la clave pública de super usuario"""
        certificado_path = os.path.join(os.getcwd(), "Usuarios", "00000000A", "00000000Acert.pem")
        # Lee el certificado y obtén la clave pública
        with open(certificado_path, "rb") as f:
            certificado_bytes = f.read()

        certificado = x509.load_pem_x509_certificate(certificado_bytes, default_backend())
        clave_publica = certificado.public_key()

        # Datos a cifrar
        message = voto.encode('utf-8')

        # Cifra los datos con la clave pública
        ciphertext = clave_publica.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def descifrar_asi(self,voto_cifrado):
        """Función que recibe un voto cifrado asimetricamente y lo descifra utilizando la clave privada"""
        directorio = "Usuarios"
        ruta_usuarios = os.path.join(os.getcwd(), directorio,"00000000A")
        archivo_clave_privada = os.path.join(ruta_usuarios, "00000000A.pem")
        with open(archivo_clave_privada, "rb") as f:
            loaded_private_key = serialization.load_pem_private_key(
                f.read(),
                password=self.clave.encode('utf-8'),  # Aquí puedes proporcionar la contraseña si la clave está cifrada
                backend=default_backend()
            )
        voto_descif = loaded_private_key.decrypt(
            voto_cifrado,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return voto_descif

    def ver_firmar(self,dni):
        """Función que recibe un usuario ,voto cifrado y cifrado-firmado y comprueba la firma"""
        usuario= self.buscar_usuario("votos-usuarios.csv",dni)
        clave_publica= self.obtener_clave_publica(dni)
        try:
            clave_publica.verify(
                bytes.fromhex(usuario[2]),
                bytes.fromhex(usuario[1]),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Error al verificar la firma: {e}")
            return False


    def obtener_clave_publica(self, dni):
        """Función que obtiene clave publica de certificado"""
        certificado_path = os.path.join(os.getcwd(), "Usuarios", f"{dni}", f"{dni}cert.pem")
        with open(certificado_path, "rb") as f:
            certificado_bytes = f.read()
        certificado = x509.load_pem_x509_certificate(certificado_bytes, default_backend())
        clave_publica = certificado.public_key()

        # Convierte la clave pública a su representación en bytes
        """clave_publica_bytes = clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )"""

        return clave_publica

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
            encryption_algorithm=serialization.BestAvailableEncryption(self.clave.encode('utf-8'))
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
                password=self.clave.encode('utf-8'),  # Aquí puedes proporcionar la contraseña si la clave está cifrada
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
                input=f"{self.clave_autoridad}\ny\ny\n",
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

    def verificar_certificado(self, dni):
        # Cargar el certificado del archivo
        certificado_path=os.path.join(os.getcwd(),"Usuarios",f"{dni}",f"{dni}cert.pem")
        ca_cert_path=os.path.join(os.getcwd(),"PKI","AC1","ac1cert.pem")
        try:
            # Construir el comando 'openssl verify'
            comando = f"openssl verify -CAfile {ca_cert_path} {certificado_path}"

            # Ejecutar el comando en el sistema operativo
            proceso = subprocess.run(comando, shell=True, check=True, text=True, capture_output=True)

            # Imprimir la salida del comando
            print(f"Salida del comando:\n{proceso.stdout}")

            # Verificar si el certificado es válido
            if "OK" in proceso.stdout:
                print("El certificado es válido.")
                return True
            else:
                print("El certificado no es válido.")
                return False
        except subprocess.CalledProcessError as e:
            print(f"Error al ejecutar el comando 'openssl verify': {e}")
            print(f"Error del comando:\n{e.stderr}")
            return False

    def is_valid_password(self, password):
        private_key_path = os.path.join(os.getcwd(), "PKI", "AC1", "privado","ca1key.pem")
        try:
            with open(private_key_path, "rb") as key_file:
                # Intentar cargar la clave privada sin descifrar completamente
                serialization.load_pem_private_key(
                    key_file.read(),
                    password=password.encode(),
                    backend=default_backend()
                )
            # Si no hay excepciones, la contraseña es válida
            return True
        except ValueError:
            # Si hay una excepción, la contraseña no es válida
            return False


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
            correcto=self.verificar_certificado(dni)
            self.ventana_registro.destroy()


# Crear una instancia de la aplicación y ejecutarla
ventana = tk.Tk()
app = AplicacionRegistro(ventana)
ventana.mainloop()
