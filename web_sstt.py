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
import regex as re                                          # Para usar expresiones regualres


BUFSIZE = 8192                                              # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 22                                     # Timout para la conexión persistente
MAX_ACCESOS = 10                                            # Nº máximo de accesos al recurso index.html
MAX_PETICIONES = 30                                         # Nº máximo de peticiones del cliente al servidor
RESPONSE_OK = "200 OK"
ERROR_400 = "400 Bad Request"
ERROR_401 = "401 Not Authorized"
ERROR_403 = "403 Forbidden"
ERROR_404 = "404 Not Found"
ERROR_405 = "405 Method Not Allowed"

MIN_COOKIE_VALUE = 1                                        # Valor mínimo de un cookie-counter

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js"}

valid_emails = ["ja.lopezsola@um.es", "f.uclesayllon@um.es"]

standart_resposne_headers = ["Server", "Content-Type", "Content-Length", "Date", "Connection", "Keep-Alive"]
standart_response = "version status\r\nServer: -\r\nContent-Type: -\r\nContent-Length: -\r\nDate: -\r\nConnection: -\r\nKeep-Alive: -\r\nSet-Cookie: -\r\n body"

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    data_encoded = data.encode()
    sent_bytes = cs.send(data_encoded)
    """ Tratar el envio fallido"""
    return sent_bytes


def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    datos_rcv = cs.recv(BUFSIZE)                            # Lee los datos que se encuentran en el socket
    """Tratar errores fallidos"""
    return datos_rcv.decode()                                 # Devolvemos los datos recibidos del socket convertidos a string


def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
        1   
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    if "Cookie" in headers:
        header_cookie = headers["Cookie"]       # Nos quedamos con el string perteneciente a la línea de cabecera cookie
        
        patron_cookie_counter = r'(?<=cookie-counter=)\d+'                     # Patrón para encontrar el valor cookie-counter
        er_cookie_counter = re.compile(patron_cookie_counter)                  # Compilamos la ER
        match_cookie_counter = er_cookie_counter.search(header_cookie)         # Buscamos el valor cookie-counter=x
        
        if(match_cookie_counter):
            cookie_counter = header_cookie[match_cookie_counter.start():match_cookie_counter.end()]     # Nos quedamos con el string perteneciente a cookie-counter
    
            value_cookie_counter = int(cookie_counter)
            
            if (value_cookie_counter >= MIN_COOKIE_VALUE & value_cookie_counter < MAX_ACCESOS):
                new_value_cookie = value_cookie_counter + 1
                return new_value_cookie
            else:
                return MAX_ACCESOS
        else:
            return 1
    else:
        return 1
        
def split_message(message):
    """Esta función separa la linea de petición de las cabeceras del cuerpo"""
    patron_separador = r'(?P<peticion>.*?)\r\n(?P<cabeceras>(.|\r\n)*?)\r\n\r\n(?P<cuerpo>.*)'
    er_separador = re.compile(patron_separador)
    match_mensaje = er_separador.match(message)
    if (match_mensaje):
        # Separo la linea de petición
        str_linea_peticion = match_mensaje.group('peticion')
        linea_peticion = {} 
        patron_linea_peticion = r'(?P<metodo>.*?) (?P<URL>.*?) (?P<version>HTTP/.\..)'
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
    return peticion != None and peticion['version'] == "HTTP/1.1"


def is_valid_method(linea_peticion):
    """Comprobar si la petición HTTP es correcta: Método, URL+Recurso y Versión HTTP"""
    metodo = linea_peticion['method']
    return metodo == "GET" or metodo == "POST"


def get_ruta_recurso(url):
    """Obtener la ruta del recurso solicitado por el cliente: index o cualquier otro"""
    if url == "/":
        return "/index.html"
    else:
        return url
        

def get_email(body):
    patron_email = r'email=(?P<email>.*?)&'
    er_email = re.compile(patron_email)
    match_email = er_email.match(body)
    if match_email:
        return match_email.group('email')
    else:
        return None

def create_response(version, status, headers, data):
    """Las cabeceras a meter ya vienen dadas. Supondremos que las básicas están"""
    linea_peticion = "{} {}\r\n".format(version, status)
    cabeceras = ""
    # Añado las básicas
    for cabecera in standart_resposne_headers:
        cabeceras = cabeceras + "{}: {}\r\n".format(cabecera, headers[cabecera])
        del headers[cabecera]
    # Añado las que me queden
    for cabecera in headers:
        cabeceras = cabeceras + "{}: {}\r\n".format(cabecera, headers[cabecera])
    body = data
    return linea_peticion+cabeceras+body


def enviar_recurso(cs, version, status, ruta_recurso, cookie):
    tam_fichero = os.stat(ruta_recurso).st_size
    fichero = os.path.basename(ruta_recurso)
    (fichero, separador, extension_fichero) = fichero.partition('.')
    with open(ruta_recurso, "r",) as recurso:
                datos_leidos = recurso.read(BUFSIZE)
                # Relleno las cabeceras básicas
                cabeceras_respuestas = {"Server":"webservidor", "Content-Type": filetypes[extension_fichero], "Content-Length":tam_fichero, "Date": datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT'), "Connection": "Keep-Alive", "Keep-Alive":TIMEOUT_CONNECTION}
                # En caso de tener que mandar la cookie, se añade
                if cookie != -1:
                    cabeceras_respuestas["Set-Cookie"] = "cookie_counter_1740={} max-age=120".format(cookie)
                mensaje = create_response(version, status, cabeceras_respuestas, datos_leidos)
                enviar_mensaje(cs, mensaje)
                # Si aún quedan datos por mandar, se mandarán ahora en el bucle
                while datos_leidos!= ' ' :
                    enviar_mensaje(cs, mensaje)
                    datos_leidos = recurso.read(BUFSIZE)

def process_web_request(cs, webroot):
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
    while (True):
        (rlist, wlist, xlist) = select.select([cs],[],[], TIMEOUT_CONNECTION)
        if not rlist:
            cerrar_conexion(cs)
            sys.exit()
        else:
            datos = recibir_mensaje(cs)
            (linea_peticion, headers, body) = split_message(datos)
            if not is_HTTP_correct(linea_peticion): # Meter aquí lo de comprobar el Host????
                """Enviar un 400 """
                logger.error("Peticion mal formada")
                enviar_recurso(cs, linea_peticion['version'], ERROR_400, webroot + "/Errores/error_400.html", -1) # Mis dudas con las version
                continue
            if not is_valid_method(linea_peticion):
                """Enviar un 405"""
                logger.error("Metodo invalido en la petición")
                enviar_recurso(cs, linea_peticion['version'], ERROR_405, webroot + "/Errores/error_405.html", -1) # Mis dudas con las version
                continue
            # Escribir cabeceras en el log
            for cabecera in headers:
                logger.info('{}: {}'.format(cabecera, headers[cabecera]))
            ruta_recurso = webroot + get_ruta_recurso(linea_peticion["URL"]) # Nada de eliminar parametros porque no se permiten los get de escuestas???
            if os.path.isfile(ruta_recurso):
                "Devolver 404"
                logger.error("Archivo {} no encontrado".format(ruta_recurso))
                enviar_recurso(cs, linea_peticion['version'], ERROR_404, webroot + "/Errores/error_404.html", -1) # Mis dudas con las version
                continue
            cookie_nesaria = False
            if ruta_recurso == webroot + "/index.html" and linea_peticion["method"] == "GET":
                cookie_nesaria = True
                cookie_counter = process_cookies(headers, cs)
                if cookie_counter == MAX_ACCESOS:
                    "devolver 403"
                    logger.error("Numero máximo de accesos excedido")
                    enviar_recurso(cs, linea_peticion['version'], ERROR_403, webroot + "/Errores/error_403.html", -1) # Mis dudas con las version
                    continue
            # Distinguir entre GET y POST
            if linea_peticion["method"] == "POST":
                email = get_email(body)
                if email in valid_emails:
                    ruta_recurso = webroot + "/email_correcto"
                else:
                    "Devolver 401"
                    logger.info("Persona no autorizada")
                    enviar_recurso(cs, linea_peticion['version'], ERROR_401, webroot + "/Errores/error_401.html", -1) # Mis dudas con las version
                    continue
            # Enviar un recurso por la red
            enviar_recurso(cs, linea_peticion['version'], RESPONSE_OK, ruta_recurso, cookie_counter if cookie_nesaria else -1)
            
            

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
                    logger.info('Processing message from {}'.format(client_addr))
                    process_web_request(client_socket, args.webroot)
                else:
                    cerrar_conexion(client_socket)     
                                                                                                              
    except KeyboardInterrupt:
        True

if __name__== "__main__":
    main()
