import os
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime

# Constantes de configuración
CARPETA_DATOS = "secure_data"
ARCHIVO_CA_KEY = os.path.join(CARPETA_DATOS, "ca_key.enc")
ARCHIVO_CA_CERT = os.path.join(CARPETA_DATOS, "ca_cert.pem")
CARPETA_USUARIOS = os.path.join(CARPETA_DATOS, "usuarios")

class CryptoApp:
    def __init__(self):
        # Inicialización de carpetas
        if not os.path.exists(CARPETA_USUARIOS):
            os.makedirs(CARPETA_USUARIOS)
        
        self.ca_private_key = None
        self.ca_public_key = None

    # --- UTILIDADES DE CIFRADO SIMÉTRICO (AES) ---
    def _get_key_from_secret(self, secret_text):
        """Genera una clave AES de 32 bytes a partir de un texto (licencia o password)."""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(secret_text.encode())
        return digest.finalize()

    def _encrypt_bytes_aes(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        # Padding para que sea múltiplo de bloque
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

    # --- REQUISITOS 2 y 3: GESTIÓN DE LA AUTORIDAD (CA) ---
    def iniciar_autoridad(self, licencia):
        key_aes = self._get_key_from_secret(licencia) # Req 3: Hash de licencia

        if os.path.exists(ARCHIVO_CA_KEY):
            print("[Info] Cargando Autoridad existente...")
            with open(ARCHIVO_CA_KEY, "rb") as f:
                enc_data = f.read()
            try:
                dec_pem = self._decrypt_bytes_aes(enc_data, key_aes)
                self.ca_private_key = serialization.load_pem_private_key(dec_pem, password=None)
                
                with open(ARCHIVO_CA_CERT, "rb") as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())
                self.ca_public_key = self.ca_cert.public_key()
                print("Autoridad cargada correctamente.")
                return True
            except Exception:
                print("ERROR: Licencia incorrecta.")
                return False
        else:
            print("[Info] Generando nueva Autoridad (CA)...")
            # Req 2: Identidad y claves propias
            self.ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.ca_public_key = self.ca_private_key.public_key()
            
            # Crear Certificado Autofirmado para la CA
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"App Authority CA")])
            self.ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                self.ca_public_key).serial_number(x509.random_serial_number()).not_valid_before(
                datetime.datetime.utcnow()).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,).sign(self.ca_private_key, hashes.SHA256())

            # Guardar Clave Privada cifrada con AES (Req 3)
            pem = self.ca_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
            enc_data = self._encrypt_bytes_aes(pem, key_aes)
            with open(ARCHIVO_CA_KEY, "wb") as f: f.write(enc_data)
            
            # Guardar Certificado Público
            with open(ARCHIVO_CA_CERT, "wb") as f: f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
            print("Autoridad inicializada y guardada.")
            return True

    # --- REQUISITOS 1, 2 y 7: GESTIÓN DE USUARIOS ---
    def crear_usuario(self, nombre, password):
        if not self.ca_private_key: return print("Error: CA no iniciada.")
        
        print(f"Generando claves para {nombre}...")
        user_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        user_pub_key = user_priv_key.public_key()

        # Req 2: Crear certificado firmado por la CA
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, nombre)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca_cert.subject).public_key(
            user_pub_key).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)).sign(self.ca_private_key, hashes.SHA256())

        # Guardar Certificado (Público)
        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.crt"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Req 7: Guardar Clave Privada cifrada con password del usuario
        key_aes_user = self._get_key_from_secret(password)
        pem_priv = user_priv_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        enc_priv = self._encrypt_bytes_aes(pem_priv, key_aes_user)
        
        with open(os.path.join(CARPETA_USUARIOS, f"{nombre}.key"), "wb") as f:
            f.write(enc_priv)
        
        print(f"Usuario {nombre} registrado exitosamente.")

    def listar_usuarios(self):
        return [f.replace(".crt", "") for f in os.listdir(CARPETA_USUARIOS) if f.endswith(".crt")]

    # --- REQUISITOS 4, 5 y 6: CIFRADO ---
    def cifrar_archivo(self, ruta_archivo, lista_usuarios_destino):
        if not self.ca_public_key: return print("Error: CA no cargada.")
        
        # 1. Generar clave simétrica para este archivo (Clave de Sesión)
        session_key = os.urandom(32) 
        
        # 2. Cifrar el contenido del archivo con la Clave de Sesión (AES)
        with open(ruta_archivo, "rb") as f: datos = f.read()
        datos_cifrados = self._encrypt_bytes_aes(datos, session_key)

        # 3. Cifrar la Clave de Sesión para cada usuario (RSA)
        cabecera_claves = {}
        
        for usuario in lista_usuarios_destino:
            path_cert = os.path.join(CARPETA_USUARIOS, f"{usuario}.crt")
            
            # Req 5: Cargar y VALIDAR certificado
            with open(path_cert, "rb") as f:
                cert_usuario = x509.load_pem_x509_certificate(f.read())
            
            try:
                # Verificamos la firma usando la clave pública de la APP (CA)
                self.ca_public_key.verify(
                    cert_usuario.signature,
                    cert_usuario.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
            except Exception:
                print(f"ALERTA: El certificado de {usuario} NO es válido. Saltando.")
                continue

            # Extraer clave pública y cifrar la session_key
            pub_key = cert_usuario.public_key()
            enc_session_key = pub_key.encrypt(
                session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            # Guardamos en hex para poder escribir en JSON
            cabecera_claves[usuario] = enc_session_key.hex()

        # 4. Guardar archivo final (Estructura: Cabecera JSON + Salto + Datos Cifrados)
        archivo_salida = ruta_archivo + ".secure"
        estructura = {
            "header": cabecera_claves,
            "data": datos_cifrados.hex()
        }
        with open(archivo_salida, "w") as f:
            json.dump(estructura, f)
        
        print(f"Archivo cifrado creado: {archivo_salida}")

    # --- REQUISITOS 8 y 9: DESCIFRADO con RSA ---

    def descifrar_archivo(self, ruta_archivo_secure, usuario, password):
        # Limpiamos espacios en blanco por si acaso
        usuario = usuario.strip()
        
        # 1. Recuperar clave privada del usuario
        path_key = os.path.join(CARPETA_USUARIOS, f"{usuario}.key")
        if not os.path.exists(path_key): 
            return print(f"ERROR: No encuentro el archivo de clave para '{usuario}'.")
        
        key_aes_user = self._get_key_from_secret(password)
        
        try:
            with open(path_key, "rb") as f: enc_priv_data = f.read()
            dec_priv_pem = self._decrypt_bytes_aes(enc_priv_data, key_aes_user)
            user_priv_key = serialization.load_pem_private_key(dec_priv_pem, password=None)
        except Exception:
            print("ERROR: La contraseña del usuario es incorrecta (No se pudo descifrar su clave privada).")
            return

        # 2. Leer archivo cifrado
        try:
            with open(ruta_archivo_secure, "r") as f:
                estructura = json.load(f)
        except FileNotFoundError:
            return print("ERROR: No encuentro el archivo cifrado (.secure)")
        
        cabecera = estructura["header"]
        datos_cifrados = bytes.fromhex(estructura["data"])

        # --- AQUÍ ESTÁ EL CAMBIO PARA AYUDARTE ---
        if usuario not in cabecera:
            print(f"\n[ERROR DE ACCESO]")
            print(f"El archivo tiene acceso para: {list(cabecera.keys())}")
            print(f"Tú estás intentando entrar como: '{usuario}'")
            print("Asegúrate de que las mayúsculas coinciden.\n")
            return

        # 3. Descifrar la Clave de Sesión
        enc_session_key = bytes.fromhex(cabecera[usuario])
        
        try:
            session_key = user_priv_key.decrypt(
                enc_session_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            # Req 9: Usar clave recuperada
            datos_originales = self._decrypt_bytes_aes(datos_cifrados, session_key)
            
            nombre_orig = ruta_archivo_secure.replace(".secure", ".decrypted.txt")
            with open(nombre_orig, "wb") as f:
                f.write(datos_originales)
            print(f"ÉXITO: Archivo recuperado en {nombre_orig}")
            
        except Exception as e:
            print(f"Error crítico descifrando: {e}")

# --- INTERFAZ DE CONSOLA ---
def main():
    app = CryptoApp()
    print("=== APLICACIÓN DE CIFRADO SEGURO ===")
    licencia = input("Introduce el NÚMERO DE LICENCIA de la App para iniciar: ")
    
    if not app.iniciar_autoridad(licencia):
        return

    while True:
        print("\n--- MENÚ ---")
        print("1. Crear nuevo usuario")
        print("2. Cifrar un archivo")
        print("3. Descifrar un archivo")
        print("4. Salir")
        opcion = input("Seleccione: ")

        if opcion == "1":
            u = input("Nombre usuario: ")
            p = input("Password usuario: ")
            app.crear_usuario(u, p)
        
        elif opcion == "2":
            archivo = input("Ruta del archivo a cifrar (ej: documento.txt): ")
            if not os.path.exists(archivo):
                print("Archivo no existe. Crea uno de prueba primero.")
                continue
            
            usuarios_disp = app.listar_usuarios()
            print(f"Usuarios disponibles: {usuarios_disp}")
            sel = input("Escribe los nombres separados por coma: ").split(",")
            sel = [s.strip() for s in sel]
            app.cifrar_archivo(archivo, sel)

        elif opcion == "3":
            archivo = input("Ruta archivo .secure: ").strip()
            u = input("Soy el usuario: ").strip()
            p = input("Mi password es: ")
            app.descifrar_archivo(archivo, u, p)
            
        elif opcion == "4":
            break

if __name__ == "__main__":
    main()