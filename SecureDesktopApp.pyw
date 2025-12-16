import os
import json
import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# --- LIBRERÍAS DE CRIPTOGRAFÍA ---
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# --- CONFIGURACIÓN ---
CARPETA_DATOS = "secure_data"
ARCHIVO_CA_KEY = os.path.join(CARPETA_DATOS, "ca_key.enc")
ARCHIVO_CA_CERT = os.path.join(CARPETA_DATOS, "ca_cert.pem")
CARPETA_USUARIOS = os.path.join(CARPETA_DATOS, "usuarios")


# ==========================================
class CryptoApp:
    def __init__(self):
        if not os.path.exists(CARPETA_USUARIOS):
            os.makedirs(CARPETA_USUARIOS)
        self.ca_private_key = None
        self.ca_public_key = None
        self.ca_cert = None

    #Convierte la contraseña en una clave AES de 256 bytes usando SHA-256
    def _get_key_from_secret(self, secret_text):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret_text.encode())
        return digest.finalize()

    # --- CIFRADO SIMÉTRICO AES ---
    def _encrypt_bytes_aes(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder() # Bloque de 128 bits (16 bytes) pq AES usa bloques de 16 bytes
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    # --- DESCIFRADO SIMÉTRICO AES ---
    def _decrypt_bytes_aes(self, encrypted_data, key):
        iv = encrypted_data[:16]
        actual_data = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(actual_data) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    # --- GESTIÓN DE AUTORIDAD ---
    def iniciar_autoridad(self, licencia):
        key_aes = self._get_key_from_secret(licencia) # Clave AES derivada de la licencia

        if os.path.exists(ARCHIVO_CA_KEY): # Cargar CA existente
            try:
                with open(ARCHIVO_CA_KEY, "rb") as f: enc_data = f.read()
                dec_pem = self._decrypt_bytes_aes(enc_data, key_aes)
                self.ca_private_key = serialization.load_pem_private_key(dec_pem, password=None)
                with open(ARCHIVO_CA_CERT, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
                self.ca_public_key = self.ca_cert.public_key()
                return True, "Autoridad cargada correctamente."
            except Exception:
                return False, "ERROR: La licencia es incorrecta."
        else:
            # Crear nueva CA
            self.ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.ca_public_key = self.ca_private_key.public_key()
            
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"App Authority CA")])
            self.ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                self.ca_public_key).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.datetime.utcnow()).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,).sign(self.ca_private_key, hashes.SHA256())

            # Guardar clave y certificado de la CA
            pem = self.ca_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
            enc_data = self._encrypt_bytes_aes(pem, key_aes)
            with open(ARCHIVO_CA_KEY, "wb") as f: f.write(enc_data)
            with open(ARCHIVO_CA_CERT, "wb") as f: f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            return True, "Nueva Autoridad (CA) generada y guardada."

    # --- GESTIÓN DE USUARIOS ---
    def crear_usuario(self, nombre, password):
        # Crear par de claves y certificado firmado por la CA para el usuario
        if not self.ca_private_key: return False, "CA no iniciada."
        
        user_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        user_pub_key = user_priv_key.public_key()

        # Crear certificado de usuario
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca_cert.subject).public_key(
            user_pub_key).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(self.ca_private_key, hashes.SHA256())

        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.crt"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        key_aes_user = self._get_key_from_secret(password)
        pem_priv = user_priv_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        enc_priv = self._encrypt_bytes_aes(pem_priv, key_aes_user)
        
        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.key"), "wb") as f:
            f.write(enc_priv)
        
        return True, f"Usuario '{nombre}' creado exitosamente."

    def listar_usuarios(self):
        if not os.path.exists(CARPETA_USUARIOS): return []
        return [f.replace(".crt", "") for f in os.listdir(CARPETA_USUARIOS) if f.endswith(".crt")]

    # --- CIFRADO ---
    def cifrar_archivo(self, ruta_archivo, lista_usuarios_destino):
        if not self.ca_public_key: return False, "CA no iniciada."
        if not lista_usuarios_destino: return False, "No seleccionaste ningún usuario."
        
        session_key = os.urandom(32) 
        try:
            with open(ruta_archivo, "rb") as f: datos = f.read()
        except Exception as e:
            return False, f"Error leyendo archivo: {e}"

        datos_cifrados = self._encrypt_bytes_aes(datos, session_key)
        cabecera_claves = {}
        
        usuarios_validos = 0
        #Verificar que el certificado es válido y firmado por la CA
        for usuario in lista_usuarios_destino:
            path_cert = os.path.join(CARPETA_USUARIOS, f"{usuario}.crt")
            if not os.path.exists(path_cert): continue

            with open(path_cert, "rb") as f:
                cert_usuario = x509.load_pem_x509_certificate(f.read())
            
            try:
                # Verificación de firma CORREGIDA
                self.ca_public_key.verify(
                    cert_usuario.signature,
                    cert_usuario.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            except Exception:
                print(f"Alerta: Certificado falso/inválido para {usuario}")
                continue

            pub_key = cert_usuario.public_key()
            enc_session_key = pub_key.encrypt(
                session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            cabecera_claves[usuario] = enc_session_key.hex()
            usuarios_validos += 1

        if usuarios_validos == 0:
            return False, "No se pudo validar ningún usuario destino."

        archivo_salida = ruta_archivo + ".secure"
        estructura = {
            "header": cabecera_claves,
            "data": datos_cifrados.hex()
        }
        with open(archivo_salida, "w") as f:
            json.dump(estructura, f)
        
        return True, f"Cifrado completado.\nArchivo generado: {archivo_salida}"

    # --- DESCIFRADO ---
    def descifrar_archivo(self, ruta_archivo_secure, usuario, password):
        usuario = usuario.strip()
        path_key = os.path.join(CARPETA_USUARIOS, f"{usuario}.key")
        if not os.path.exists(path_key): 
            return False, f"El usuario '{usuario}' no existe."
        
        key_aes_user = self._get_key_from_secret(password)
        
        try:
            with open(path_key, "rb") as f: enc_priv_data = f.read()
            dec_priv_pem = self._decrypt_bytes_aes(enc_priv_data, key_aes_user)
            user_priv_key = serialization.load_pem_private_key(dec_priv_pem, password=None)
        except Exception:
            return False, "Contraseña de usuario incorrecta."

        try:
            with open(ruta_archivo_secure, "r") as f:
                estructura = json.load(f)
        except Exception:
            return False, "El archivo no es válido o no se encuentra."
        
        cabecera = estructura["header"]
        datos_cifrados = bytes.fromhex(estructura["data"])

        if usuario not in cabecera:
            return False, f"ACCESO DENEGADO.\nEste archivo solo es para: {list(cabecera.keys())}"

        enc_session_key = bytes.fromhex(cabecera[usuario])
        
        try:
            session_key = user_priv_key.decrypt(
                enc_session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            datos_originales = self._decrypt_bytes_aes(datos_cifrados, session_key)
            
            nombre_orig = ruta_archivo_secure.replace(".secure", ".decrypted.txt")
            with open(nombre_orig, "wb") as f:
                f.write(datos_originales)
            
            return True, f"Archivo recuperado exitosamente en:\n{nombre_orig}"
            
        except Exception as e:
            return False, f"Error crítico al descifrar: {e}"


# ==========================================
# INTERFAZ GRÁFICA (FRONTEND TKINTER)
# ==========================================
class AppGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistema de Archivos Seguros (PKI)")
        self.root.geometry("600x450")
        self.app_logic = CryptoApp()
        
        self.mostrar_login()

    def limpiar_ventana(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    # --- PANTALLA DE LOGIN (LICENCIA) ---
    def mostrar_login(self):
        self.limpiar_ventana()
        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True)

        ttk.Label(frame, text="SEGURIDAD CORPORATIVA", font=("Helvetica", 16, "bold")).pack(pady=10)
        ttk.Label(frame, text="Ingrese Licencia Maestra para iniciar la Autoridad:").pack(pady=5)
        
        self.entry_licencia = ttk.Entry(frame, show="*", width=30)
        self.entry_licencia.pack(pady=5)
        self.entry_licencia.focus()
        
        ttk.Button(frame, text="INICIAR SISTEMA", command=self.accion_login).pack(pady=15)
        
        ttk.Label(frame, text="(Si es la primera vez, se creará una CA nueva)", foreground="gray").pack(pady=20)

    def accion_login(self):
        licencia = self.entry_licencia.get()
        if not licencia:
            messagebox.showwarning("Error", "La licencia no puede estar vacía.")
            return

        exito, msg = self.app_logic.iniciar_autoridad(licencia)
        if exito:
            messagebox.showinfo("Bienvenido", msg)
            self.mostrar_panel_principal()
        else:
            messagebox.showerror("Error de Acceso", msg)

    # --- PANEL PRINCIPAL (PESTAÑAS) ---
    def mostrar_panel_principal(self):
        self.limpiar_ventana()
        
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Pestaña 1: Usuarios
        frame_users = ttk.Frame(notebook)
        notebook.add(frame_users, text=' Gestión Usuarios ')
        self.setup_tab_usuarios(frame_users)

        # Pestaña 2: Cifrar
        frame_enc = ttk.Frame(notebook)
        notebook.add(frame_enc, text=' Cifrar Archivo ')
        self.setup_tab_cifrar(frame_enc)

        # Pestaña 3: Descifrar
        frame_dec = ttk.Frame(notebook)
        notebook.add(frame_dec, text=' Descifrar Archivo ')
        self.setup_tab_descifrar(frame_dec)

        # Botón Salir
        ttk.Button(self.root, text="Cerrar Sesión", command=self.mostrar_login).pack(pady=5)

    # --- PESTAÑA USUARIOS ---
    def setup_tab_usuarios(self, parent):
        frame = ttk.Frame(parent, padding=20)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="Registrar Nuevo Usuario", font=("Arial", 12)).pack(anchor='w', pady=10)
        
        ttk.Label(frame, text="Nombre de Usuario:").pack(anchor='w')
        self.entry_new_user = ttk.Entry(frame)
        self.entry_new_user.pack(fill='x', pady=5)

        ttk.Label(frame, text="Contraseña Personal:").pack(anchor='w')
        self.entry_new_pass = ttk.Entry(frame, show="*")
        self.entry_new_pass.pack(fill='x', pady=5)

        ttk.Button(frame, text="Crear Usuario", command=self.accion_crear_usuario).pack(pady=15)

        # Lista de usuarios existentes
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=10)
        ttk.Label(frame, text="Usuarios en el sistema:", foreground="blue").pack(anchor='w')
        self.lbl_lista_usuarios = ttk.Label(frame, text="...")
        self.lbl_lista_usuarios.pack(anchor='w', pady=5)
        self.actualizar_lista_visual()

    def actualizar_lista_visual(self):
        users = self.app_logic.listar_usuarios()
        texto = ", ".join(users) if users else "(No hay usuarios)"
        self.lbl_lista_usuarios.config(text=texto)

    def accion_crear_usuario(self):
        u = self.entry_new_user.get()
        p = self.entry_new_pass.get()
        if u and p:
            exito, msg = self.app_logic.crear_usuario(u, p)
            if exito:
                messagebox.showinfo("Éxito", msg)
                self.entry_new_user.delete(0, 'end')
                self.entry_new_pass.delete(0, 'end')
                self.actualizar_lista_visual()
                self.recargar_lista_cifrado() # Actualizar la otra pestaña
            else:
                messagebox.showerror("Error", msg)
        else:
            messagebox.showwarning("Faltan datos", "Complete nombre y contraseña.")

    # --- PESTAÑA CIFRAR ---
    def setup_tab_cifrar(self, parent):
        frame = ttk.Frame(parent, padding=20)
        frame.pack(fill='both', expand=True)

        # Selección de Archivo
        bloque_archivo = ttk.LabelFrame(frame, text="1. Seleccionar Archivo")
        bloque_archivo.pack(fill='x', pady=5)
        
        self.lbl_archivo_sel = ttk.Label(bloque_archivo, text="Ningún archivo seleccionado", foreground="red")
        self.lbl_archivo_sel.pack(side='left', padx=10, pady=10)
        ttk.Button(bloque_archivo, text="Buscar...", command=self.seleccionar_archivo_cifrar).pack(side='right', padx=10, pady=10)

        # Selección de Destinatarios
        bloque_users = ttk.LabelFrame(frame, text="2. Seleccionar Destinatarios (Ctrl+Click para varios)")
        bloque_users.pack(fill='both', expand=True, pady=10)

        self.listbox_users = tk.Listbox(bloque_users, selectmode='multiple', height=5)
        self.listbox_users.pack(fill='both', expand=True, padx=10, pady=10)
        self.recargar_lista_cifrado()

        # Botón Acción
        ttk.Button(frame, text="CIFRAR DOCUMENTO", command=self.accion_cifrar).pack(pady=10)

    def seleccionar_archivo_cifrar(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.archivo_a_cifrar = filename
            self.lbl_archivo_sel.config(text=os.path.basename(filename), foreground="green")

    def recargar_lista_cifrado(self):
        self.listbox_users.delete(0, 'end')
        for u in self.app_logic.listar_usuarios():
            self.listbox_users.insert('end', u)

    def accion_cifrar(self):
        if not hasattr(self, 'archivo_a_cifrar'):
            messagebox.showwarning("Atención", "Seleccione primero un archivo.")
            return

        indices = self.listbox_users.curselection()
        seleccionados = [self.listbox_users.get(i) for i in indices]
        
        if not seleccionados:
            messagebox.showwarning("Atención", "Seleccione al menos un usuario destinatario.")
            return

        exito, msg = self.app_logic.cifrar_archivo(self.archivo_a_cifrar, seleccionados)
        if exito:
            messagebox.showinfo("Cifrado Exitoso", msg)
        else:
            messagebox.showerror("Error", msg)

    # --- PESTAÑA DESCIFRAR ---
    def setup_tab_descifrar(self, parent):
        frame = ttk.Frame(parent, padding=20)
        frame.pack(fill='both', expand=True)

        # Selección Archivo
        bloque_archivo = ttk.LabelFrame(frame, text="Archivo Encriptado (.secure)")
        bloque_archivo.pack(fill='x', pady=5)
        
        self.lbl_archivo_dec = ttk.Label(bloque_archivo, text="Seleccione archivo .secure", foreground="red")
        self.lbl_archivo_dec.pack(side='left', padx=10, pady=10)
        ttk.Button(bloque_archivo, text="Buscar...", command=self.seleccionar_archivo_descifrar).pack(side='right', padx=10, pady=10)

        # Credenciales
        bloque_cred = ttk.LabelFrame(frame, text="Sus Credenciales")
        bloque_cred.pack(fill='x', pady=10)
        
        ttk.Label(bloque_cred, text="Su Usuario:").grid(row=0, column=0, padx=5, pady=5)
        self.entry_dec_user = ttk.Entry(bloque_cred)
        self.entry_dec_user.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

        ttk.Label(bloque_cred, text="Su Contraseña:").grid(row=1, column=0, padx=5, pady=5)
        self.entry_dec_pass = ttk.Entry(bloque_cred, show="*")
        self.entry_dec_pass.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        ttk.Button(frame, text="DESCIFRAR Y ABRIR", command=self.accion_descifrar).pack(pady=20)

    def seleccionar_archivo_descifrar(self):
        filename = filedialog.askopenfilename(filetypes=[("Archivos Seguros", "*.secure")])
        if filename:
            self.archivo_a_descifrar = filename
            self.lbl_archivo_dec.config(text=os.path.basename(filename), foreground="green")

    def accion_descifrar(self):
        if not hasattr(self, 'archivo_a_descifrar'):
            messagebox.showwarning("Atención", "Seleccione el archivo .secure")
            return
        
        u = self.entry_dec_user.get()
        p = self.entry_dec_pass.get()
        
        if u and p:
            exito, msg = self.app_logic.descifrar_archivo(self.archivo_a_descifrar, u, p)
            if exito:
                messagebox.showinfo("Éxito", msg)
            else:
                messagebox.showerror("Fallo de Seguridad", msg)
        else:
            messagebox.showwarning("Atención", "Introduzca sus credenciales.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AppGUI(root)
    root.mainloop()