import os
import json
import datetime
import glob
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
CARPETA_MENSAJES = os.path.join(BASE_DIR, "mensajes_red") # Simula la nube/servidor
ARCHIVO_CA_KEY = os.path.join(BASE_DIR, "ca_key.enc")
ARCHIVO_CA_CERT = os.path.join(BASE_DIR, "ca_cert.pem")

class SecureChat:
    def __init__(self):
        # Crear estructura de directorios
        for d in [BASE_DIR, CARPETA_USUARIOS, CARPETA_MENSAJES]:
            if not os.path.exists(d):
                os.makedirs(d)
        
        self.ca_private_key = None
        self.ca_public_key = None
        self.ca_cert = None

    # --- UTILIDADES AES (Mismo motor que antes) ---
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

    # --- GESTIÓN DE AUTORIDAD (Igual que caso 2) ---
    def iniciar_sistema(self, licencia):
        key_aes = self._get_key_from_secret(licencia)

        if os.path.exists(ARCHIVO_CA_KEY):
            print("[SISTEMA] Cargando Autoridad existente...")
            try:
                with open(ARCHIVO_CA_KEY, "rb") as f: enc_data = f.read()
                dec_pem = self._decrypt_bytes_aes(enc_data, key_aes)
                self.ca_private_key = serialization.load_pem_private_key(dec_pem, password=None)
                with open(ARCHIVO_CA_CERT, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
                self.ca_public_key = self.ca_cert.public_key()
                return True
            except Exception:
                print("ERROR: Licencia incorrecta. No se puede iniciar el sistema.")
                return False
        else:
            print("[SISTEMA] Configurando nueva Autoridad de Certificación...")
            self.ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.ca_public_key = self.ca_private_key.public_key()
            
            # Certificado de la CA
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Secure Chat Authority")])
            self.ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                self.ca_public_key).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.datetime.utcnow()).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,).sign(self.ca_private_key, hashes.SHA256())

            # Guardar CA cifrada con la licencia
            pem = self.ca_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
            enc_data = self._encrypt_bytes_aes(pem, key_aes)
            with open(ARCHIVO_CA_KEY, "wb") as f: f.write(enc_data)
            with open(ARCHIVO_CA_CERT, "wb") as f: f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            return True

    # --- GESTIÓN DE USUARIOS ---
    def registrar_usuario(self, nombre, password):
        if not self.ca_private_key: return print("Error: Sistema no iniciado.")
        
        # Generar par de claves RSA para el usuario
        user_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        user_pub = user_priv.public_key()

        # Generar certificado firmado por la CA
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca_cert.subject).public_key(
            user_pub).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(self.ca_private_key, hashes.SHA256())

        # Guardar certificado público
        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.crt"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Guardar clave privada cifrada con la password del usuario
        key_aes_user = self._get_key_from_secret(password)
        pem_priv = user_priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        enc_priv = self._encrypt_bytes_aes(pem_priv, key_aes_user)
        
        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.key"), "wb") as f:
            f.write(enc_priv)
        
        print(f"Usuario '{nombre}' registrado en el chat.")

    def listar_usuarios(self):
        return [os.path.basename(f).replace(".crt", "") for f in glob.glob(os.path.join(CARPETA_USUARIOS, "*.crt"))]

    # --- LÓGICA DE ENVÍO DE MENSAJES ---
    def enviar_mensaje(self, remitente, mensaje_texto, destinatarios):
        if not self.ca_public_key: return print("Error: CA no cargada.")
        
        # 1. Crear clave de sesión (AES) efímera para este mensaje
        session_key = os.urandom(32)
        
        # 2. Cifrar el cuerpo del mensaje
        # Convertimos texto a bytes y ciframos
        mensaje_bytes = mensaje_texto.encode('utf-8')
        mensaje_cifrado = self._encrypt_bytes_aes(mensaje_bytes, session_key)

        # 3. Preparar cabeceras para cada destinatario
        cabeceras = {}
        
        print(f"Cifrando mensaje para: {destinatarios}...")
        
        for dest in destinatarios:
            dest = dest.strip()
            path_cert = os.path.join(CARPETA_USUARIOS, f"{dest}.crt")
            
            if not os.path.exists(path_cert):
                print(f"Warning: Usuario '{dest}' no existe. Omitiendo.")
                continue

            # Validar Certificado
            with open(path_cert, "rb") as f:
                cert_obj = x509.load_pem_x509_certificate(f.read())
            
            try:
                self.ca_public_key.verify(
                    cert_obj.signature,
                    cert_obj.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256(), # Hash corregido
                )
            except Exception:
                print(f"ALERTA: Certificado de '{dest}' inválido/falsificado. Omitiendo.")
                continue

            # Cifrar la clave de sesión con la RSA pública del destinatario
            pub_key = cert_obj.public_key()
            encrypted_session_key = pub_key.encrypt(
                session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            cabeceras[dest] = encrypted_session_key.hex()

        if not cabeceras:
            return print("Error: No se pudo cifrar para ningún destinatario válido.")

        # 4. Empaquetar el 'Payload' (JSON)
        paquete = {
            "fecha": str(datetime.datetime.now()),
            "remitente": remitente,
            "headers": cabeceras, # Diccionario {usuario: clave_sesion_cifrada}
            "contenido": mensaje_cifrado.hex()
        }

        # 5. 'Enviar' a la red (Guardar archivo)
        nombre_archivo = f"msg_{int(datetime.datetime.now().timestamp())}_{remitente}.json"
        ruta_final = os.path.join(CARPETA_MENSAJES, nombre_archivo)
        
        with open(ruta_final, "w") as f:
            json.dump(paquete, f, indent=4)
            
        print(f"Mensaje enviado y almacenado en: {nombre_archivo}")

    # --- LÓGICA DE RECEPCIÓN (BUZÓN) ---
    def leer_buzon(self, usuario, password):
        usuario = usuario.strip()
        print(f"\n--- BUZÓN DE {usuario.upper()} ---")
        
        # 1. Intentar cargar la clave privada del usuario
        path_key = os.path.join(CARPETA_USUARIOS, f"{usuario}.key")
        if not os.path.exists(path_key): return print("Usuario no existe.")
        
        key_aes_user = self._get_key_from_secret(password)
        try:
            with open(path_key, "rb") as f: enc_priv = f.read()
            dec_priv = self._decrypt_bytes_aes(enc_priv, key_aes_user)
            user_priv_key = serialization.load_pem_private_key(dec_priv, password=None)
        except Exception:
            return print("Contraseña incorrecta. No se puede acceder al buzón.")

        # 2. Escanear todos los mensajes en la 'red'
        archivos_msgs = glob.glob(os.path.join(CARPETA_MENSAJES, "*.json"))
        mensajes_encontrados = 0

        if not archivos_msgs:
            print("(No hay mensajes en el servidor)")
            return

        for ruta_msg in archivos_msgs:
            with open(ruta_msg, "r") as f:
                paquete = json.load(f)
            
            # Verificar si este mensaje es para mí
            cabeceras = paquete.get("headers", {})
            if usuario in cabeceras:
                mensajes_encontrados += 1
                remitente = paquete.get("remitente", "Desconocido")
                fecha = paquete.get("fecha", "")
                
                # 3. Descifrado Híbrido
                try:
                    # A. Descifrar la clave de sesión con mi RSA Privada
                    enc_session_key = bytes.fromhex(cabeceras[usuario])
                    session_key = user_priv_key.decrypt(
                        enc_session_key,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )
                    
                    # B. Descifrar el contenido con la clave de sesión (AES)
                    contenido_cifrado = bytes.fromhex(paquete["contenido"])
                    contenido_plano = self._decrypt_bytes_aes(contenido_cifrado, session_key)
                    
                    # Mostrar
                    print(f"[{fecha}] De: {remitente}")
                    print(f"Mensaje: {contenido_plano.decode('utf-8')}")
                    print("-" * 40)
                    
                except Exception as e:
                    print(f"[{fecha}] Error al descifrar mensaje de {remitente}: {e}")
        
        if mensajes_encontrados == 0:
            print("No tienes mensajes nuevos.")

# --- MENÚ DE CONSOLA ---
def main():
    chat = SecureChat()
    print("=== CHAT SEGURO (RSA + AES) ===")
    
    # IMPORTANTE: Si borraste la carpeta, usa una licencia nueva. 
    # Si la carpeta existe, usa LA MISMA licencia o fallará.
    licencia = input("Introduce la LICENCIA del Servidor de Chat: ")
    if not chat.iniciar_sistema(licencia):
        return

    while True:
        print("\n1. Registrar Usuario")
        print("2. Enviar Mensaje")
        print("3. Leer Mi Buzón")
        print("4. Ver usuarios registrados")
        print("5. Salir")
        
        op = input("Opción: ")

        if op == "1":
            u = input("Nuevo usuario: ")
            p = input("Password: ")
            chat.registrar_usuario(u, p)
        
        elif op == "2":
            remitente = input("¿Quién eres? (Tu usuario): ")
            # Simulamos autenticación simple pidiendo password antes de enviar (opcional en chat real, pero buena práctica)
            # Aquí lo saltamos por agilidad, asumimos que si envías es porque eres tú.
            
            usuarios = chat.listar_usuarios()
            print(f"Contactos: {usuarios}")
            dest = input("Destinatario(s) (separados por coma): ").split(",")
            msg = input("Escribe tu mensaje: ")
            
            chat.enviar_mensaje(remitente, msg, dest)

        elif op == "3":
            u = input("Usuario: ")
            p = input("Password: ")
            chat.leer_buzon(u, p)
            
        elif op == "4":
            print("Usuarios:", chat.listar_usuarios())
            
        elif op == "5":
            break

if __name__ == "__main__":
    main()