# 🔍 PCAP Network Traffic Analyzer

La herramienta procesa paquetes de red filtrados por protocolos clave (IP, DNS, HTTP) mediante el motor de **Wireshark/TShark**, extrayendo datos analíticos clave y generando un informe estructurado en formato **JSON** listo para integraciones con SIEM o reportes de seguridad.

---

## 🚀 Características Principales

- **Filtrado Eficiente de Tráfico:** Procesamiento enfocado únicamente en capas IP, DNS y HTTP.
- **Top Direcciones IP de Destino:** Identificación y conteo de los destinos con mayor volumen de tráfico.
- **Detección de Consultas DNS:** Extracción y deduplicación de dominios consultados en la captura.
- **Inspección de Peticiones HTTP:** Mapeo de métodos (`GET`, `POST`), hosts y URIs solicitadas.
- **Reporte Automático Organizado:** Creación dinámica de la carpeta `reports/` y exportación limpia en formato JSON (`pcap_report.json`).

---

## 🛠️ Requisitos Previos

1. **Python 3.10+**
2. **Wireshark / TShark:** Es **imprescindible** tener instalado Wireshark en el sistema operativo, ya que `pyshark` utiliza el ejecutable `tshark` de Wireshark para el parsing de paquetes.
   - En Windows, asegurarse de que TShark esté incluido en la instalación por defecto.
   - En Linux, sudo apt install tshark
---

## 📦 Instalación y Configuración

1. **Clonar el repositorio:**
   ```bash
   git clone [https://github.com/RodasF06/pcap-network-analyzer.git]
   cd pcap-network-analyzer

Crear y activar el entorno virtual:

En Windows (PowerShell):
```bash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
En Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```
Instalar dependencias:
```bash
pip install -r requirements.txt
```
## 🎯 Modo de Uso

Coloca el archivo .pcap o .pcapng que deseas analizar dentro de la carpeta samples/ (por ejemplo, samples/sample_traffic.pcap).

Ejecuta el script principal: 
```bash
python pcap_analyzer.py
```
El análisis procesará la captura y guardará el informe estructurado automáticamente en reports/pcap_report.json.

## 📁 Estructura del Proyecto

```text
pcap-network-analyzer/
├── samples/                # Capturas de red de entrada (.pcap)
│   └── sample_traffic.pcap
├── reports/                # Reportes JSON generados
│   └── pcap_report.json
├── .gitignore              # Archivos y carpetas excluidos de Git
├── pcap_analyzer.py        # Script principal de análisis
├── README.md               # Documentación del proyecto
└── requirements.txt        # Librerías de Python requeridas

📄 Ejemplo de Salida (JSON)

{
    "summary": {
        "total_packets_analyzed": 42,
        "top_destination_ips": [
            {
                "ip": "192.168.1.1",
                "count": 12
            }
        ]
    },
    "dns_queries": [
        "example.com"
    ],
    "http_requests": []
}

---