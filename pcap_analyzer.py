import pyshark
import json
from collections import Counter
import os
import asyncio
import sys
from pathlib import Path

def analyze_pcap(pcap_file):
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    if not os.path.exists(pcap_file):
        print(f"[!] Error: El archivo '{pcap_file}' no existe. Asegúrate de colocarlo en la carpeta 'samples/'.")
        return
    
    print(f"[*] Analizando archivo: {pcap_file}...\n")
    
    # Cargar captura de red con filtro para capturar solo IP, DNS y HTTP
    cap = pyshark.FileCapture(pcap_file, display_filter="ip or dns or http")
    
    destination_ips = []
    dns_requests = []
    http_methods = []
    
    for packet in cap:
        try:
            # 1. Extraer direcciones IP de destino
            if 'IP' in packet:
                destination_ips.append(packet.ip.dst)
                
            # 2. Extraer peticiones DNS (Dominios consultados)
            if 'DNS' in packet and hasattr(packet.dns, 'qry_name'):
                dns_requests.append(packet.dns.qry_name)
                
            # 3. Extraer métodos y URIs en tráfico HTTP
            if 'HTTP' in packet:
                if hasattr(packet.http, 'request_method') and hasattr(packet.http, 'request_uri'):
                    http_methods.append({
                        "method": packet.http.request_method,
                        "host": getattr(packet.http, 'host', 'N/A'),
                        "uri": packet.http.request_uri
                    })
        except AttributeError:
            continue

    cap.close()

    # Generar resumen con las IPs más frecuentes
    top_ips = Counter(destination_ips).most_common(5)
    unique_dns = list(set(dns_requests))

    # Construir el reporte final de IoCs
    report = {
        "summary": {
            "total_packets_analyzed": len(destination_ips),
            "top_destination_ips": [{"ip": ip, "count": count} for ip, count in top_ips]
        },
        "dns_queries": unique_dns,
        "http_requests": http_methods
    }
    
# ----------- RUTA DEL REPORTE --------------
    # Crear el directorio 'reports' si no existe
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    # Definir la ruta completa dentro de la carpeta reports
    output_filename = os.path.join(reports_dir, "pcap_report.json")
    
    with open(output_filename, "w") as f:
        json.dump(report, f, indent=4)
        
    print(f"[+] Análisis completado con éxito. Reporte guardado en: {output_filename}")

if __name__ == "__main__":
    # Buscar todos los archivos .pcap o .pcapng dentro de samples/
    samples_dir = Path("samples")
    pcap_files = list(samples_dir.glob("*.pcap")) + list(samples_dir.glob("*.pcapng"))

    if pcap_files:
        # Toma el primer archivo .pcap que encuentre en la carpeta
        target_file = str(pcap_files[0])
        analyze_pcap(target_file)
    else:
        print("[!] Error: No se encontraron archivos .pcap en la carpeta 'samples/'.")