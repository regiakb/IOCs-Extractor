# IOCs Extractor form .pcap file

Python script to extract all IPs/domains from a .pcap file into different txt files.


## Dependencies

To install dependencies:

```python
  pip install -r requirements.txt
```


    

## Usage/Examples

```python
python3 iocs_extractor.py -h
    usage: iocs_extractor.py [-h] -p PCAP [-i] [-d]

    Analiza un archivo .pcap y extrae las IPs y dominios, los guarda en archivos
    txt diferentes. Solo muestra valores únicos, elimina los duplicados.

    options:
    -h, --help            show this help message and exit
    -p PCAP, --pcap PCAP  Archivo .pcap a procesar
    -i, --ips             Extraer IPs del archivo .pcap
    -d, --dominios        Extraer dominios del archivo .pcap

```

