# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors                                            #https://docs.python.org/3/library/selectors.html
import select
import types                                                # Para definir el tipo de datos data
import argparse                                             # Leer parametros de ejecución
import os                                                   # Obtener ruta y extension
from datetime import datetime, timedelta                    # Fechas de los mensajes HTTP
import time                                                 # Timeout conexión
import sys                                                  # sys.exit
import re                                                   # Analizador sintáctico
import logging                                              # Para imprimir logs

BUFSIZE = 8192                                              # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 22                                     # Timout para la conexión persistente

MAX_ACCESOS = 11                                            # Nº máximo de accesos al recurso index.html
MAX_PETICIONES = 30                                         # Nº máximo de peticiones del cliente al servidor
MIN_COOKIE_VALUE = 1                                        # Valor mínimo de un cookie-counter
NO_VALID_VALUE = 0                                          # Valor no válido de la cookie

# Códigos a devolver en los HTTP response
ACCEPT_CODE = "200 OK"
ERROR_MESSAGE_400 = "400 Bad Request"
ERROR_MESSAGE_401 = "401 Unauthorized"
ERROR_MESSAGE_403 = "403 Forbidden"
ERROR_MESSAGE_404 = "404 Not Found"
ERROR_MESSAGE_405 = "405 Method Not Allowed"

# Nombre del servidor
SERVER_NAME = "web.serviciostelematicos1740.org"

# Valores que deben tomar los campos de la cookie en la respuesta
NOMBRE_COOKIE = "cookie_counter_1740"
TIMEOUT_COOKIE = 120

# Tipo de fichero por defecto
TYPE_FICH_DEF = "text/plain"

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js", "mp4": "video/mp4", "ogg": "audio/ogg", "ico":"image/ico", "mp3":"audio/mpeg"}

# Ficheros html usados en respuestas
html = {"index":"/index.html", "mail":"/accion_form.html", "400":"/Errores/error_400.html", "401":"/Errores/error_401.html", "403":"/Errores/error_403.html",
        "404":"/Errores/error_404.html","405":"/Errores/error_405.html"}

# Correos válidos para el formulario a rellenar
valid_emails = ["ja.lopezsola%40um.es", "f.uclesayllon%40um.es"]

# Cabeceras a enviar en respuesta
headers = {"vers":"HTTP/1.1 {}\r\n", "server":"Server: {}\r\n", "cont-ty":"Content-Type: {}\r\n", "cont-lng":"Content-Length: {}\r\n",
           "date":"Date: {}\r\n", "conn":"Connection: {}\r\n", "cookie":"Set-Cookie: {}={}; Max-Age={}\r\n", "keep":"Keep-Alive: timeout={}\r\n"}



# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()



def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    try:
        sent_bytes = cs.send(data)
        
        if (sent_bytes == 0):
            logger.error("Error al tratar de enviar datos por el socket, cerramos la conexión")  
            cerrar_conexion(cs)
            sys.exit(1)
        
        return sent_bytes
    except Exception:
        """ Tratar el envio fallido"""
        logger.error("Se produjo una excepción al usar el socket para enviar datos. Cerramos la conexión")
        cerrar_conexion(cs)
        sys.exit(1)
    

def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    try:
        datos_rcv = cs.recv(BUFSIZE)                            # Lee los datos que se encuentran en el socket
        
        if (not datos_rcv):
            logger.error("Error al tratar de recibir datos por el socket, cerramos la conexión")  
            cerrar_conexion(cs)
            sys.exit(1)
        
        return datos_rcv.decode()                               # Devolvemos los datos recibidos del socket convertidos a string
    except Exception:
        logger.error("Se produjo una excepción al usar el socket para recibir datos. Cerramos la conexión")
        cerrar_conexion(cs)
        sys.exit(1)


def process_cookies(headers):
    """ Esta función procesa la cookie cookie_counter
        1   
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    if "Cookie" in headers:
        header_cookie = headers["Cookie"]                                           # Nos quedamos con el string perteneciente a la línea de cabecera cookie
        patron_cookie_counter = r'(?<=cookie_counter_1740=)\d+'                     # Patrón para encontrar el valor cookie-counter
        er_cookie_counter = re.compile(patron_cookie_counter)                       # Compilamos la ER
        match_cookie_counter = er_cookie_counter.search(header_cookie)              # Buscamos el valor cookie-counter=x 
        if match_cookie_counter:
            cookie_counter = header_cookie[match_cookie_counter.start():match_cookie_counter.end()]     # Nos quedamos con el string perteneciente a cookie-counter
            value_cookie_counter = int(cookie_counter)            
            if (value_cookie_counter >= MIN_COOKIE_VALUE and value_cookie_counter < MAX_ACCESOS):
                new_value_cookie = value_cookie_counter + 1
                return new_value_cookie
            else:
                return MAX_ACCESOS
        else:
            return MIN_COOKIE_VALUE
    else:
        return MIN_COOKIE_VALUE
    
        
def split_message(message):
    """Esta función separa la linea de petición de las cabeceras del cuerpo"""
    patron_separador = r'(?P<peticion>.*?)\r\n(?P<cabeceras>(.|\r\n)*?)\r\n\r\n(?P<cuerpo>.*)'
    er_separador = re.compile(patron_separador)
    match_mensaje = er_separador.match(message)
    if (match_mensaje):
        # Separo la linea de petición
        str_linea_peticion = match_mensaje.group('peticion')
        linea_peticion = {} 
        patron_linea_peticion = r'(?P<metodo>(GET|POST|HEAD|PUT|DELETE)) (?P<URL>.*?) (?P<version>HTTP/1.1)'
        er_linea_peticion = re.compile(patron_linea_peticion)
        match_linea_peticion = er_linea_peticion.match(str_linea_peticion)
        if match_linea_peticion:
            linea_peticion['method'] = match_linea_peticion.group('metodo')
            linea_peticion['URL'] = match_linea_peticion.group('URL')
            linea_peticion['version'] = match_linea_peticion.group('version')
        else:
            logger.error("La linea de peticion es incorrecta")
            return (None, None, None)
        # Separo las cabeceras
        str_cabeceras = match_mensaje.group('cabeceras')
        cabeceras = {}
        patron_cabeceras = r'(?P<cabecera>.*?): (?P<valor>.*?)\r\n'
        er_cabeceras = re.compile(patron_cabeceras)
        for cabecera in er_cabeceras.finditer(str_cabeceras):
            cabeceras[cabecera.group('cabecera')] = cabecera.group('valor')
        # Separo el cuerpo
        cuerpo = match_mensaje.group('cuerpo')
        return (linea_peticion, cabeceras, cuerpo)
    else:
        logger.error("No se encontró la estructura de una peticion HTTP")
        return (None, None, None)


def is_HTTP_correct(peticion):
    """Comprueba si la peticion HTTP es correcta"""
    return peticion != None


def is_valid_method(linea_peticion, body):
    """Comprobar si la petición HTTP es correcta: Método, URL+Recurso y Versión HTTP"""
    return ((linea_peticion["method"] == "GET") and (body == "")) or ((linea_peticion["method"] == "POST") and (body != ""))


def comprobar_Host(headers):
    return "Host" in headers


def get_ruta_recurso(webroot, url):
    """Obtener la ruta del recurso solicitado por el cliente: index o cualquier otro"""
    if (url == "/"):
        return webroot + html["index"]
    else:
        return webroot + url    
        

def get_email(body):
    patron_email = r'email=(?P<email>.+)(?=(&| |\r\n|))'
    er_email = re.compile(patron_email)
    match_email = er_email.match(body)
    if match_email:
        return match_email.group('email')
    else:
        logger.error("Email no encontrado")
        return None


def obtener_extension (ruta_recurso):
    fichero = os.path.basename(ruta_recurso)                        # Nos devuelve el nombre en forma: (nombre.extensión)
    componentes_fichero = fichero.split(".")                        # Obtenemos una lista de la forma: (nombre, extensión)
    extension_fichero = componentes_fichero[1]                      # Nos quedamos con la extensión del fichero
    return extension_fichero


def headers_response_comunes(codigo_resp, extension, tam_body):
    """Define las cabeceras de la respuesta HTTP comunes tanto para un mensaje de error como de OK"""
    # Si la extensión no está en nuestro diccionario, devolvermos una por defecto: text/plain
    if (not extension in filetypes):
        type_fich = TYPE_FICH_DEF
    else:  
        type_fich = filetypes[extension]            
    
    # Construimos el mensaje
    response = (headers["vers"].format(codigo_resp) + headers["server"].format(SERVER_NAME) + headers["cont-ty"].format(type_fich) 
                + headers["cont-lng"].format(tam_body) + headers["date"].format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')) 
                + headers["conn"].format("Keep-Alive") + headers["keep"].format(TIMEOUT_CONNECTION))
    
    return response


def create_response_error(error_message, recurso_body):
    """Enviar una respuesta de error"""
    # Leer el body, sacar su tamaño y su extensión
    tam_recurso_body = os.stat(recurso_body).st_size
    extension_body = obtener_extension(recurso_body)
    
    # Crear la respuesta
    response = headers_response_comunes(error_message, extension_body, tam_recurso_body)
    response = response + "\r\n"
                                       
    return response.encode()                                               # Lo devolvemos en bytes
    

def create_response_ok(linea_peticion, extension, cookie_counter, tam_body):
    """Enviar una respuesta de OK a la petición"""
    response = headers_response_comunes(ACCEPT_CODE, extension, tam_body)
    
    # Si el recurso pedido es /index.html debemos añadir la cabecera cookie
    if ( (linea_peticion["method"] == "GET") and (linea_peticion["URL"] == "/") ):
        # En Set-Cookie hay que poner cookie_counter_1740 y Max-Age solo se envía si es pertinente (no hay que enviarlo constantemente o la cookie no expirará)
        response = response + headers["cookie"].format(NOMBRE_COOKIE, cookie_counter, TIMEOUT_COOKIE)
    
    response = response + "\r\n"
    return response.encode()                                               # Lo devolvemos en bytes    


def send_response (cs, response, recurso):
    """Enviar una respuesta HTTP por el socket"""
    with open(recurso, "rb",) as rec:
        datos_recurso = rec.read(BUFSIZE)
        datos_leidos = response + datos_recurso 
        enviar_mensaje(cs, datos_leidos)    
        
        datos_leidos = rec.read(BUFSIZE)
                                   
        while (datos_leidos != b""):
            enviar_mensaje(cs, datos_leidos)
            datos_leidos = rec.read(BUFSIZE)
        
        logger.info("Respuesta enviada")
                    

def process_web_request(cs, webroot, cliente):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)

        * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()

            * Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
              sin recibir ningún mensaje o hay datos. Se utiliza select.select

            * Si no es por timeout y hay datos en el socket cs.
                * Leer los datos con recv.
                * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1
                    * Devuelve una lista con los atributos de las cabeceras.
                    * Comprobar si la versión de HTTP es 1.1
                    * Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".
                    * Leer URL y eliminar parámetros si los hubiera
                    * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html
                    * Construir la ruta absoluta del recurso (webroot + recurso solicitado)
                    * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"
                    * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar
                      el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                      Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    * Obtener el tamaño del recurso en bytes.
                    * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type
                    * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y
                      las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                      Content-Length y Content-Type.
                    * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.
                    * Se abre el fichero en modo lectura y modo binario
                        * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                        * Cuando ya no hay más información para leer, se corta el bucle

            * Si es por timeout, se cierra el socket tras el período de persistencia.
                * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
    """
    cookie_counter = NO_VALID_VALUE  
    peticiones = 0
    while peticiones < MAX_PETICIONES:
        (rlist, wlist, xlist) = select.select([cs],[],[], TIMEOUT_CONNECTION)
        if not rlist:
            cerrar_conexion(cs)
            logger.info("Conexión persistente del cliente {} finalizada".format(cliente))
            sys.exit()
        else:
            peticiones = peticiones + 1
            logger.info("Procesando petición del cliente {}".format(cliente))
            logger.debug("Número de petición: {}".format(peticiones))
            datos = recibir_mensaje(cs)
            (linea_peticion, headers, body) = split_message(datos)
            if (not is_HTTP_correct(linea_peticion)):
                """Enviar un 400"""
                logger.error("No se ha hecho una petición con el formato de línea de petición adecuado: Método + URL + HTTP/1.1")
                ruta_recurso = webroot + html["400"]
                response = create_response_error(ERROR_MESSAGE_400, ruta_recurso)
                send_response(cs, response, ruta_recurso)
                continue
            if (not is_valid_method(linea_peticion, body)):
                """Enviar un 405"""
                logger.error("El método utilizado ({}) no es válido, debe ser GET o POST".format(linea_peticion["method"]))
                ruta_recurso = webroot + html["405"]
                response = create_response_error(ERROR_MESSAGE_405, ruta_recurso)
                send_response(cs, response, ruta_recurso)
                continue
            logger.debug("Línea de petición: {} {} {}".format(linea_peticion["method"], linea_peticion["URL"], linea_peticion["version"]))
            # Escribir cabeceras en el log
            for cabecera in headers:
                logger.info('{}: {}'.format(cabecera, headers[cabecera]))
            if comprobar_Host(headers):
                logger.info("Se ha incluido la cabecera Host")
            ruta_recurso = get_ruta_recurso(webroot, linea_peticion["URL"])
            if (not os.path.isfile(ruta_recurso)):
                """Enviar un 404"""
                logger.error("Archivo {} no encontrado".format(ruta_recurso))
                ruta_recurso = webroot + html["404"]
                response = create_response_error(ERROR_MESSAGE_404, ruta_recurso)
                send_response(cs, response, ruta_recurso)
                continue 
            logger.info("Sirviendo archivo {}".format(ruta_recurso))
            if ( (linea_peticion["method"] == "GET") and (ruta_recurso == (webroot + html["index"]))):
                cookie_counter = process_cookies(headers)
                if (cookie_counter == MAX_ACCESOS):
                    """Enviar un 403"""
                    logger.error("Se ha excedido el número máximo de accesos ({}) al recurso index.html, debe esperar 2 "
                                "minutos desde su última petición. Cerraremos la conexión mientras tanto".format(MAX_ACCESOS-1))
                    ruta_recurso = webroot + html["403"]
                    response = create_response_error(ERROR_MESSAGE_403, ruta_recurso)
                    send_response(cs, response, ruta_recurso)
                    cerrar_conexion(cs)
                    sys.exit()
            if (linea_peticion["method"] == "POST"):
                email = get_email(body)
                logger.debug("Email indicado en el formulario: {}".format(email))
                if email in valid_emails:
                    ruta_recurso = webroot + html["mail"]
                else:
                    """Enviar un 401"""
                    logger.error("Persona no autorizada ({})".format(email))
                    ruta_recurso = webroot + html["401"] 
                    response = create_response_error(ERROR_MESSAGE_401, ruta_recurso)
                    send_response(cs, response, ruta_recurso)
                    continue
            # Calcular tamaño del fichero y extensión del que debemos leer
            tam_fichero = os.stat(ruta_recurso).st_size  
            extension_fichero = obtener_extension(ruta_recurso)                               
            # Crear respuesta
            response = create_response_ok(linea_peticion, extension_fichero, cookie_counter, tam_fichero)
            # Enviar respuesta
            send_response(cs, response, ruta_recurso)
    
    logger.info("Número máximo de peticiones alcanzadas por el cliente {}".format(cliente))
    cerrar_conexion(cs)
    logger.info("Conexión con el cliente {} cerrada".format(cliente))
    sys.exit()
             

def main():
    """ Función principal del servidor
    """

    try:
        # Argument parser para obtener la ip y puerto de los parámetros de ejecución del programa. IP por defecto 0.0.0.0
        parser = argparse.ArgumentParser()
        parser.add_argument("-p", "--port", help="Puerto del servidor", type=int, required=True)
        parser.add_argument("-ip", "--host", help="Dirección IP del servidor o localhost", required=True)
        parser.add_argument("-wb", "--webroot", help="Directorio base desde donde se sirven los ficheros (p.ej. /home/user/mi_web)")
        parser.add_argument('--verbose', '-v', action='store_true', help='Incluir mensajes de depuración en la salida')
        args = parser.parse_args()
        print(args.host, args.port)
        if args.verbose:
            logger.setLevel(logging.DEBUG)
        # Comprobamos si se ha pasado como webroot una estructura de la forma: /../../ y en ese caso quitamos el último /
        if (args.webroot[len(args.webroot)-1] == "/"):
            args.webroot = args.webroot[:len(args.webroot)-1]
        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))
        logger.info("Serving files from {}".format(args.webroot))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto = 0) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            status = server_socket.bind((args.host, args.port))
            if status == -1:
                logger.error('Error al tratar de establecer la conexión')
                sys.exit(1)
            server_socket.listen()
            while True:
                (client_socket, client_addr) = server_socket.accept()
                logger.info('Accepting connection from {} address'.format(client_addr))
                child_pid = os.fork()
                if child_pid == -1:
                    logger.error('No child created')
                elif child_pid == 0:
                    cerrar_conexion(server_socket)
                    process_web_request(client_socket, args.webroot, client_addr)
                else:
                    cerrar_conexion(client_socket)     
                                                                                                              
    except KeyboardInterrupt:
        True

if __name__== "__main__":
    main()
