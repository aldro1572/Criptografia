import os
import json
import datetime
import glob
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# --- LIBRERÍAS CRIPTOGRÁFICAS ---
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# --- CONFIGURACIÓN DE CARPETAS ---
BASE_DIR = "chat_seguro_data"
CARPETA_USUARIOS = os.path.join(BASE_DIR, "usuarios")
CARPETA_MENSAJES = os.path.join(BASE_DIR, "mensajes_red")
ARCHIVO_CA_KEY = os.path.join(BASE_DIR, "ca_key.enc")
ARCHIVO_CA_CERT = os.path.join(BASE_DIR, "ca_cert.pem")

# ==========================================
# LÓGICA DE NEGOCIO (BACKEND ADAPTADO)
# ==========================================
class SecureChatBackend:
    def __init__(self):
        for d in [BASE_DIR, CARPETA_USUARIOS, CARPETA_MENSAJES]:
            if not os.path.exists(d):
                os.makedirs(d)
        
        self.ca_private_key = None
        self.ca_public_key = None
        self.ca_cert = None

    def _get_key_from_secret(self, secret_text):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret_text.encode())
        return digest.finalize()

    def _encrypt_bytes_aes(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def _decrypt_bytes_aes(self, encrypted_data, key):
        iv = encrypted_data[:16]
        actual_data = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(actual_data) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    # --- AUTORIDAD (CA) ---
    def iniciar_sistema(self, licencia):
        key_aes = self._get_key_from_secret(licencia)

        if os.path.exists(ARCHIVO_CA_KEY):
            try:
                with open(ARCHIVO_CA_KEY, "rb") as f: enc_data = f.read()
                dec_pem = self._decrypt_bytes_aes(enc_data, key_aes)
                self.ca_private_key = serialization.load_pem_private_key(dec_pem, password=None)
                with open(ARCHIVO_CA_CERT, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
                self.ca_public_key = self.ca_cert.public_key()
                return True, "Sistema cargado correctamente."
            except Exception:
                return False, "Licencia incorrecta."
        else:
            # Generar nueva CA
            self.ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.ca_public_key = self.ca_private_key.public_key()
            
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Secure Chat Authority")])
            self.ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                self.ca_public_key).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.datetime.utcnow()).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,).sign(self.ca_private_key, hashes.SHA256())

            pem = self.ca_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
            enc_data = self._encrypt_bytes_aes(pem, key_aes)
            with open(ARCHIVO_CA_KEY, "wb") as f: f.write(enc_data)
            with open(ARCHIVO_CA_CERT, "wb") as f: f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            return True, "Nuevo Sistema de Chat inicializado."

    # --- USUARIOS ---
    def registrar_usuario(self, nombre, password):
        if not self.ca_private_key: return False, "Sistema no iniciado."
        
        user_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        user_pub = user_priv.public_key()

        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca_cert.subject).public_key(
            user_pub).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(self.ca_private_key, hashes.SHA256())

        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.crt"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        key_aes_user = self._get_key_from_secret(password)
        pem_priv = user_priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        enc_priv = self._encrypt_bytes_aes(pem_priv, key_aes_user)
        
        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.key"), "wb") as f:
            f.write(enc_priv)
        
        return True, f"Usuario '{nombre}' registrado."

    def listar_usuarios(self):
        return [os.path.basename(f).replace(".crt", "") for f in glob.glob(os.path.join(CARPETA_USUARIOS, "*.crt"))]

    # --- ENVÍO ---
    def enviar_mensaje(self, remitente, mensaje_texto, destinatarios):
        if not self.ca_public_key: return False, "Error CA."
        
        session_key = os.urandom(32)
        mensaje_bytes = mensaje_texto.encode('utf-8')
        mensaje_cifrado = self._encrypt_bytes_aes(mensaje_bytes, session_key)

        cabeceras = {}
        log_errores = []
        
        for dest in destinatarios:
            dest = dest.strip()
            path_cert = os.path.join(CARPETA_USUARIOS, f"{dest}.crt")
            
            if not os.path.exists(path_cert):
                log_errores.append(f"Usuario {dest} no existe.")
                continue

            with open(path_cert, "rb") as f:
                cert_obj = x509.load_pem_x509_certificate(f.read())
            
            try:
                self.ca_public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            except Exception:
                log_errores.append(f"Certificado de {dest} inválido.")
                continue

            pub_key = cert_obj.public_key()
            encrypted_session_key = pub_key.encrypt(
                session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            cabeceras[dest] = encrypted_session_key.hex()

        if not cabeceras:
            return False, f"No se pudo enviar. Errores: {log_errores}"

        paquete = {
            "fecha": str(datetime.datetime.now()),
            "remitente": remitente,
            "headers": cabeceras,
            "contenido": mensaje_cifrado.hex()
        }

        nombre_archivo = f"msg_{int(datetime.datetime.now().timestamp())}_{remitente}.json"
        ruta_final = os.path.join(CARPETA_MENSAJES, nombre_archivo)
        
        with open(ruta_final, "w") as f:
            json.dump(paquete, f, indent=4)
            
        return True, "Mensaje enviado a la red."

    # --- RECEPCIÓN (Modificado para devolver lista de textos) ---
    def obtener_mensajes_descifrados(self, usuario, password):
        usuario = usuario.strip()
        path_key = os.path.join(CARPETA_USUARIOS, f"{usuario}.key")
        if not os.path.exists(path_key): return False, ["Usuario no encontrado."]
        
        key_aes_user = self._get_key_from_secret(password)
        try:
            with open(path_key, "rb") as f: enc_priv = f.read()
            dec_priv = self._decrypt_bytes_aes(enc_priv, key_aes_user)
            user_priv_key = serialization.load_pem_private_key(dec_priv, password=None)
        except Exception:
            return False, ["Contraseña incorrecta."]

        archivos_msgs = glob.glob(os.path.join(CARPETA_MENSAJES, "*.json"))
        lista_mensajes = []
        encontrados = 0

        if not archivos_msgs:
            return True, ["(La red está vacía, no hay mensajes)"]

        # Ordenar por fecha (truco usando el timestamp del nombre)
        archivos_msgs.sort(reverse=True)

        for ruta_msg in archivos_msgs:
            try:
                with open(ruta_msg, "r") as f: paquete = json.load(f)
            except: continue
            
            cabeceras = paquete.get("headers", {})
            if usuario in cabeceras:
                encontrados += 1
                remitente = paquete.get("remitente", "Anon")
                fecha = paquete.get("fecha", "---")
                
                try:
                    enc_session_key = bytes.fromhex(cabeceras[usuario])
                    session_key = user_priv_key.decrypt(
                        enc_session_key,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )
                    
                    contenido_cifrado = bytes.fromhex(paquete["contenido"])
                    contenido_plano = self._decrypt_bytes_aes(contenido_cifrado, session_key)
                    
                    texto_msg = f"FECHA: {fecha}\nDE: {remitente}\nMENSAJE:\n{contenido_plano.decode('utf-8')}\n" + ("-"*40)
                    lista_mensajes.append(texto_msg)
                    
                except Exception as e:
                    lista_mensajes.append(f"[ERROR] Mensaje de {remitente} corrupto o hackeado: {e}")
        
        if encontrados == 0:
            return True, ["No tienes mensajes nuevos."]
        
        return True, lista_mensajes

# ==========================================
# INTERFAZ GRÁFICA (FRONTEND TKINTER)
# ==========================================
class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Seguro (E2EE)")
        self.root.geometry("650x500")
        self.backend = SecureChatBackend()
        
        self.mostrar_login()

    def limpiar(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def mostrar_login(self):
        self.limpiar()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(expand=True)

        ttk.Label(frame, text="SERVIDOR DE CHAT SEGURO", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(frame, text="Licencia del Servidor:").pack()
        self.entry_licencia = ttk.Entry(frame, show="*")
        self.entry_licencia.pack(pady=5)
        
        ttk.Button(frame, text="CONECTAR AL SISTEMA", command=self.accion_login).pack(pady=15)

    def accion_login(self):
        lic = self.entry_licencia.get()
        if not lic: return messagebox.showwarning("Error", "Falta licencia")
        
        ok, msg = self.backend.iniciar_sistema(lic)
        if ok:
            messagebox.showinfo("Sistema", msg)
            self.mostrar_dashboard()
        else:
            messagebox.showerror("Error", msg)

    def mostrar_dashboard(self):
        self.limpiar()
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # Tab 1: Registrar
        f_reg = ttk.Frame(notebook)
        notebook.add(f_reg, text=' Registro ')
        self.setup_registro(f_reg)

        # Tab 2: Enviar
        f_send = ttk.Frame(notebook)
        notebook.add(f_send, text=' Redactar ')
        self.setup_enviar(f_send)

        # Tab 3: Buzón
        f_inbox = ttk.Frame(notebook)
        notebook.add(f_inbox, text=' Mi Buzón ')
        self.setup_buzon(f_inbox)

        ttk.Button(self.root, text="Desconectar", command=self.mostrar_login).pack(pady=5)

    # --- PESTAÑA REGISTRO ---
    def setup_registro(self, frame):
        frm = ttk.Frame(frame, padding=20)
        frm.pack(fill='both')
        
        ttk.Label(frm, text="Nuevo Usuario:", font=("Arial", 10, "bold")).pack(anchor='w')
        self.entry_reg_user = ttk.Entry(frm)
        self.entry_reg_user.pack(fill='x', pady=5)
        
        ttk.Label(frm, text="Contraseña:", font=("Arial", 10, "bold")).pack(anchor='w')
        self.entry_reg_pass = ttk.Entry(frm, show="*")
        self.entry_reg_pass.pack(fill='x', pady=5)
        
        ttk.Button(frm, text="Crear Cuenta", command=self.accion_registro).pack(pady=15)

    def accion_registro(self):
        u, p = self.entry_reg_user.get(), self.entry_reg_pass.get()
        if u and p:
            ok, msg = self.backend.registrar_usuario(u, p)
            if ok:
                messagebox.showinfo("Éxito", msg)
                self.entry_reg_user.delete(0, 'end')
                self.entry_reg_pass.delete(0, 'end')
                self.recargar_usuarios()
            else:
                messagebox.showerror("Error", msg)

    # --- PESTAÑA ENVIAR ---
    def setup_enviar(self, frame):
        frm = ttk.Frame(frame, padding=10)
        frm.pack(fill='both', expand=True)

        # De quién
        ttk.Label(frm, text="De (Remitente):").pack(anchor='w')
        self.combo_remitente = ttk.Combobox(frm)
        self.combo_remitente.pack(fill='x', pady=2)

        # Para quién
        ttk.Label(frm, text="Para (Destinatarios - Selecciona varios con Ctrl):").pack(anchor='w', pady=(10,0))
        self.list_dest = tk.Listbox(frm, selectmode='multiple', height=4)
        self.list_dest.pack(fill='x', pady=2)
        
        # Mensaje
        ttk.Label(frm, text="Mensaje:").pack(anchor='w', pady=(10,0))
        self.text_msg = tk.Text(frm, height=5)
        self.text_msg.pack(fill='both', expand=True, pady=2)

        ttk.Button(frm, text="ENVIAR MENSAJE CIFRADO", command=self.accion_enviar).pack(pady=5)
        
        self.recargar_usuarios() # Llenar listas al inicio

    def recargar_usuarios(self):
        # Actualiza las listas de la pestaña Enviar
        users = self.backend.listar_usuarios()
        self.combo_remitente['values'] = users
        self.list_dest.delete(0, 'end')
        for u in users:
            self.list_dest.insert('end', u)

    def accion_enviar(self):
        remitente = self.combo_remitente.get()
        msg = self.text_msg.get("1.0", 'end-1c')
        
        indices = self.list_dest.curselection()
        destinatarios = [self.list_dest.get(i) for i in indices]

        if not remitente or not destinatarios or not msg.strip():
            return messagebox.showwarning("Faltan datos", "Rellena remitente, destinatarios y mensaje.")

        ok, txt = self.backend.enviar_mensaje(remitente, msg, destinatarios)
        if ok:
            messagebox.showinfo("Enviado", txt)
            self.text_msg.delete("1.0", 'end')
        else:
            messagebox.showerror("Error envío", txt)

    # --- PESTAÑA BUZÓN ---
    def setup_buzon(self, frame):
        frm = ttk.Frame(frame, padding=10)
        frm.pack(fill='both', expand=True)

        # Login para descifrar
        top_frm = ttk.Frame(frm)
        top_frm.pack(fill='x')
        
        ttk.Label(top_frm, text="Usuario:").pack(side='left')
        self.entry_inbox_user = ttk.Entry(top_frm, width=15)
        self.entry_inbox_user.pack(side='left', padx=5)
        
        ttk.Label(top_frm, text="Pass:").pack(side='left')
        self.entry_inbox_pass = ttk.Entry(top_frm, show="*", width=15)
        self.entry_inbox_pass.pack(side='left', padx=5)
        
        ttk.Button(top_frm, text="DESCIFRAR MIS MENSAJES", command=self.accion_leer).pack(side='left', padx=10)

        # Área de visualización
        self.area_mensajes = scrolledtext.ScrolledText(frm, state='disabled', height=15)
        self.area_mensajes.pack(fill='both', expand=True, pady=10)

    def accion_leer(self):
        u, p = self.entry_inbox_user.get(), self.entry_inbox_pass.get()
        if not u or not p: return messagebox.showwarning("Login", "Introduce usuario y contraseña")

        ok, lista = self.backend.obtener_mensajes_descifrados(u, p)
        
        self.area_mensajes.config(state='normal')
        self.area_mensajes.delete('1.0', 'end')
        
        if ok:
            for m in lista:
                self.area_mensajes.insert('end', m + "\n\n")
        else:
            messagebox.showerror("Error", lista[0])
            
        self.area_mensajes.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()