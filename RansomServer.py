import http.server
import ssl
import socketserver

PORT = 4443

# Definimos el manejador de peticiones (sirve archivos del directorio actual)
Handler = http.server.SimpleHTTPRequestHandler

# Creamos el servidor TCP
httpd = socketserver.TCPServer(("localhost", PORT), Handler)

# ENVOLTORIO SSL (Aquí ocurre la "magia" del HTTPS)
# Cargamos el certificado falso y la clave privada
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print(f"Servidor 'Banco Falso' escuchando en https://localhost:{PORT}")
print("Esperando víctimas...")

httpd.serve_forever()