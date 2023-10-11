import csv
import base64

# Datos en formato de cadena de bytes
datos_bytes = b'Estos son datos en formato de cadena de bytes'
# Convertir los datos binarios a Base64
datos_base64 = datos_bytes.hex()

# Nombre del archivo CSV
nombre_archivo = 'datos.csv'

# Escribir los datos en el archivo CSV como una cadena de texto
with open(nombre_archivo, 'w', newline='') as archivo_csv:
    escritor_csv = csv.writer(archivo_csv)
    escritor_csv.writerow([datos_base64])

# Leer los datos desde el archivo CSV y decodificarlos
with open(nombre_archivo, 'r') as archivo_csv:
    lector_csv = csv.reader(archivo_csv)
    fila = next(lector_csv)
    datos_leidos_hexa = fila[0]
    datos_leidos = bytes.fromhex(datos_leidos_hexa)

# Verificar los datos leídos
print("Datos leídos:", datos_leidos)
