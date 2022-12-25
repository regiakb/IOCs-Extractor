import argparse
import scapy.all as scapy
from tqdm import tqdm

# Crear un analizador de argumentos con argparse
parser = argparse.ArgumentParser(description="Analiza un archivo .pcap y extrae las IPs y dominios, los guarda en archivos txt diferentes. Solo muestra valores únicos, elimina los duplicados.")
# Añadir un argumento para especificar el archivo .pcap
parser.add_argument("-p", "--pcap", required=True, help="Archivo .pcap a procesar")
# Añadir un argumento opcional para especificar qué información se desea extraer del archivo .pcap
parser.add_argument("-i", "--ips", action="store_true", help="Extraer IPs del archivo .pcap")
parser.add_argument("-d", "--dominios", action="store_true", help="Extraer dominios del archivo .pcap")

# Procesar los argumentos
args = parser.parse_args()

# Mostrar el mensaje "Cargando archivo .pcap"
print("Cargando archivo .pcap")

# Abrir el archivo .pcap especificado como argumento
pcap = scapy.rdpcap(args.pcap)

# Crear conjuntos vacíos para almacenar las IPs, dominios y URLs encontrados
ips = set()
dominios = set()

# Crear una barra de progreso con la opción dynamic_ncols habilitada
barra_progreso = tqdm(total=len(pcap), dynamic_ncols=True)



# Recorrer cada paquete del archivo .pcap
for paquete in pcap:
    # Actualizar la barra de progreso
    barra_progreso.update(1)

    # Si el paquete tiene un campo IP (es decir, es un paquete IP)
    if paquete.haslayer(scapy.IP):
        # Añadir la IP origen y destino del paquete al conjunto de IPs
        ips.add(paquete[scapy.IP].src)
        ips.add(paquete[scapy.IP].dst)

    # Si el paquete tiene un campo DNS (es decir, es un paquete DNS)
    if paquete.haslayer(scapy.DNS):
        # Añadir el dominio solicitado en el paquete al conjunto de dominios
        dominios.add(paquete[scapy.DNS].qd.qname.decode())


# Cerrar la barra de progreso
barra_progreso.close()

# Si se ha especificado la opción de extraer IPs
if args.ips:
    print("Escribiendo las IPs \n")
    # Abrir un archivo txt para escribir las IPs
    with open("ips.txt", "w") as f:
        # Escribir las IPs en el archivo, una por línea
        for ip in ips:
            f.write(ip + "\n")

# Si se ha especificado la opción de extraer dominios
if args.dominios:
    print("Escribiendo los dominios \n")
    # Abrir un archivo txt para escribir los dominios
    with open("dominios.txt", "w") as f:
        # Escribir los dominios en el archivo, uno por línea
        for dominio in dominios:
            f.write(dominio + "\n")


