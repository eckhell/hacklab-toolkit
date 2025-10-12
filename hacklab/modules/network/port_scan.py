"""
Módulo port-scan
- scan_host(host: str, ports: Iterable[int], timeout: float = 1.0, workers: int = 100) -> dict

Devuelve un dict JSON-serializable con:
{
  "host": "127.0.0.1",
  "scanned": 3,
  "open_ports": [12345],
  "raw": [
    {"port": 22, "open": False, "error": "connrefused"},
    {"port": 12345, "open": True},
    {"port": 80, "open": False, "error": "timeout"}
  ]
}
"""

from __future__ import annotations
from typing import Iterable, List, Dict
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

class ScanError(Excepcion): 
    # Excepción lanzada en errores de validación
    pass

logger = logging.getLogger(__name__)

def _probe(host: str, port: int, timeout: float) -> Dict:
    """
    Intenta conectar mediante TCP a (host, port) con un timeout y devuelve en un dict.
    """
    try:
        sock = socket.create.connection((host, port), timeout=timeout)
        sock.close()
        return{"port": port, "open": True}
    except socket.timeout: # No hubo respuesta en el tiempo dado
        return{"port": port, "open": False, "error": "timeout"}
    except ConnectionRefusedError: # La máquina responde "no hay servicio aqui"
        return{"port": port, "open": False, "error":"refused"}
    except socket.gaierror: # Error de resolución DNS (host inválido)
        return{"port": port, "open": False, "error":"gaierror"}
    except OSError as e: # Captura errores de bajo nivel
        return{"port": port, "open": False, "error":str(e)}
    
def scan_host(host:str, ports: Iterable[int], timeout: float = 1.0, workers: int = 100) -> Dict:
    """
    Escanea los puertos dados en host. Devuelve un dict con resumen y resultados por puerto
    """

    try: 
        resolved = socket.gethostbyname(host)
        logger.debug("Host %s resuelto a %s", host, resolved)
    except socket.gaierror:
        raise ScanError(f"Host desconocido o no resolvible: {host}")
    
    ports_list = list(ports)
    valid_ports: list[int] = []
    for port in ports_list:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            raise ScanError(f"Puerto no válido: {port}")
        if not (1 <= pi <= 65535): 
            raise ScanError(f"Puerto fuera de rango (1-65535):{port}")
        valid_ports.append(pi)

    ports_list = sorted(set(valid_ports))
    if not ports_list:
        raise ScanError("No se han proporcionado puertos a escanear")
    
    max_workers = min(max(1, workers), len(ports_list))
    logger.info("Iniciando scan host=%s puertos=%d timeoout=%.2f workers=%d", host, len(ports_list), timeout, max_workers)

    results: List[Dict] = []
    future_to_port = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for port in ports_list:
            future = executor.submit(_probe, host, port, timeout)
            future_to_port[future] = port

        for fut in as_completed(future_to_port):
            port = future_to_port[future]
            try: 
                res = fut.result()
                results.append(res)
            except Exception as e:
                logger.exception(f"Exception al sondear {host}:{port}")
                results.append({"port": port, "open": False, "error": f"exception: {e}"})
    
    results_sorted = sorted(results, key=lambda x: x["port"])
    open_ports = [r["port"] for r in results_sorted if r.get("open")]

    return {"host":host, "scanned": len(ports_list), "open_ports": open_ports, "raw": results_sorted}