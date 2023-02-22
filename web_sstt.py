# coding=utf-8
#!/usr/bin/env python3

import socket
import selectors                                                        #https://docs.python.org/3/library/selectors.html
import select
import types                                                            # Para definir el tipo de datos data
import argparse                                                         # Leer parametros de ejecución
import os                                                               # Obtener ruta y extension
from datetime import datetime, timedelta                                # Fechas de los mensajes HTTP
import time                                                             # Timeout conexión
import sys                                                              # sys.exit
import re                                                               # Analizador sintáctico
import logging                                                          # Para imprimir logs
import regex as re                                                      # Para usar expresiones regualres



BUFSIZE = 8192                                                          # Tamaño máximo del buffer que se puede utilizar
TIMEOUT_CONNECTION = 22                                                 # Timout para la conexión persistente: 1 + 7 + 4 + 0 + 20 = 22
MAX_ACCESOS = 10                                                        # Nº máximo de accesos al recurso index.html
MAX_PETICIONES = 30                                                     # Nº máximo de peticiones del cliente al servidor
MIN_COOKIE_VALUE = 1                                                    # Valor mínimo de un cookie-counter

# Terna de valores para acceder al diccionario que contiene la línea de petición (método usado, recurso solicitado, versión HTTP)
METODO = "method"
URL = "url"
VERSION = "version"

# Código a devolver cuando la solicitud del cliente es correctas
ACCEPT_CODE = "200"
ACCEPT_MESSAGE = "OK"

# Códigos a devolver cuando la solicitud del cliente es incorrecta
ERROR_CODE_400 = "400"
ERROR_CODE_401 = "401"
ERROR_CODE_403 = "403"
ERROR_CODE_404 = "404"
ERROR_CODE_405 = "405"

ERROR_MESSAGE_400 = "Bad Request"
ERROR_MESSAGE_401 = "Unauthorized"
ERROR_MESSAGE_403 = "Forbidden"
ERROR_MESSAGE_404 = "Not Found"
ERROR_MESSAGE_405 = "Method Not Allowed"

# Versión de HTTP que usa este servidor
VERSION = "HTTP/1.1"

# Nombre del servidor
SERVER_NAME = "web.ceronaturalistas1740.org"

# Valores que deben tomar los campos de la cookie en la respuesta
NOMBRE_COOKIE = "cookie_counter_1740"
EXPIRE_TIME = 120                                                       # 2 minutos = 120 segundos (unidad que se debe indicar en Max-Age)

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js"}

# Correos válidos para el formulario a rellenar
valid_emails = ["ja.lopezsola@um.es", "f.uclesayllon@um.es"]

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()                                                          # Permite cerrar la conexión que establece el socket
    
    
def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """    
    bytes_snd = cs.send(data)                                           # Los datos ya están codificados en bytes, por lo que no necesitamos una codificación extra
        
    if (bytes_snd == 0):
        logger.error("Error al tratar de enviar datos por el socket")  
        cerrar_conexion(cs)
        sys.exit(1)
                           
    return bytes_snd                                                    # Devolvemos el nº de bytes enviados


def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    datos_rcv = cs.recv(BUFSIZE)                                        # Lee los datos que se encuentran en el socket
    
    """Tratar errores fallidos"""
    if (not datos_rcv):
        logger.error("Error al tratar de recibir datos por el socket")  
        cerrar_conexion(cs)
        sys.exit(1)
    
    return datos_rcv.decode()                                           # Devolvemos los datos recibidos del socket convertidos a string
    
    # pass                                                              # Se utiliza cuando las funciones están vacías para que no de errores


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    # Si encontramos la cabecera cookie en el diccionario de cabeceras de la petición HTTP nos quedamos con el valor almacenado en el diccionario
    if ("Cookie" in headers):
        header_cookie = headers["Cookie"]                  
        
        patron_cookie_counter = r'(?<=cookie_counter_1740=)\d+'                                         # Patrón para encontrar el valor cookie-counter
        er_cookie_counter = re.compile(patron_cookie_counter)                                           # Compilamos la ER
        match_cookie_counter = er_cookie_counter.search(header_cookie)                                  # Buscamos el valor cookie-counter=x
        
        if(match_cookie_counter):
            cookie_counter = header_cookie[match_cookie_counter.start():match_cookie_counter.end()]     # Nos quedamos con el string perteneciente a cookie-counter
    
            value_cookie_counter = int(cookie_counter)
            
            if (value_cookie_counter == MAX_ACCESOS):
                return MAX_ACCESOS
            
            if (value_cookie_counter >= MIN_COOKIE_VALUE and value_cookie_counter < MAX_ACCESOS):
                new_value_cookie = value_cookie_counter + 1
                return new_value_cookie
        else:
            return MIN_COOKIE_VALUE
    else:
        return MIN_COOKIE_VALUE


def split_message(message):
    """Esta función separa la linea de petición de las cabeceras del cuerpo y el cuerpo del mensaje"""
    # 1º Obtenemos la línea de petición en el formato: (método, URL + posibles parámetros, versión HTTP usada)
    patron_linea_peticion = r'(GET|POST|HEAD|PUT|DELETE) (/.*?)(\?.+? | )(HTTP/1.1)'
    er_linea_peticion = re.compile(patron_linea_peticion)
    match_linea_peticion = er_linea_peticion.search(message)
    
    linea_peticion = {}
    
    if (match_linea_peticion):
        linea_peticion[METODO] = match_linea_peticion.group(1)
        linea_peticion[URL] = match_linea_peticion.group(2)
        linea_peticion[VERSION] = match_linea_peticion.group(4)
        
    # 2º Obtenemos las cabeceras en formato de diccionario: {'cabecera1:valor1', ... 'cabeceraN:valorN}
    headers = {}
    
    patron_header = r'(.+?):(.+)'
    er_header = re.compile(patron_header)
    for match_header in er_header.finditer(message):
        headers[match_header.group(1)] = match_header.group(2)
        
    # 3º Obtenemos el cuerpo de la petición: Es una cadena, ¡Importante, si no se encuentra nada, será None!
    patron_body = r'(?<=\r\n\r\n).+'
    er_body = re.compile(patron_body)
    match_body = er_body.search(message)
    
    if (match_body):
        body = message[match_body.start():match_body.end()]
    else:
        body = match_body                                           # Devuelvo un None
    
    return (linea_peticion, headers, body)


def is_HTTP_correct(linea_peticion):
    """Comprueba si la peticion HTTP es correcta: Método, URL + Recurso y Versión HTTP"""
    if linea_peticion:                                             # Devuelve True si posee elementos en su interior, 
        return True                                                # Por la ER desarrollada sabemos que contiene un método válido y la versión HTTP correcta
    else:
        return False


def is_valid_method(linea_peticion, body):
    """Comprobar si la petición usa un método GET o POST"""
    # Si usamos el método get el cuerpo debe ser None (no hay nada), si usamos el post necesitamos que haya un cuerpo
    if ( ((linea_peticion[METODO] == "GET") and (body is None )) or ((linea_peticion[METODO] == "POST") and (body is not None)) ):
        return True
    else:
        return False


def get_ruta_recurso(linea_peticion, webroot):
    """Obtener la ruta del recurso solicitado por el cliente: index o cualquier otro"""
    url = linea_peticion[URL]
    
    if (url == "/"):
        ruta_recurso = webroot + "index.html"
    else:
        ruta_recurso = webroot + url[1:]                           # Nos saltamos el carácter / de la url ya que está incluido en la webroot
    
    return ruta_recurso
    

def get_email(body):
    """Obtener el email del formulario que se ha rellenado"""
    patron_email = r'(?<=email=)(.+?)(?=(&| ))'
    er_email = re.compile(patron_email)
    match_email = er_email.search(body)
    
    if (match_email):
        email = body[match_email.start():match_email.end()]
    else:
        email = match_email
    
    # ¡Importante, puede devolver el valor None!
    return email


def leer_recurso(recurso):
    """Obtener los datos que contiene un recurso. El valor devuelto será en bytes"""
        
    with open(recurso, "rb",) as rec:
        datos_recurso = rec.read(BUFSIZE)
        datos_leidos = datos_recurso                                
        
        while (datos_leidos != b""):
            datos_leidos = rec.read(BUFSIZE)
            datos_recurso = datos_recurso + datos_leidos
    
    return datos_recurso


def obtener_extension (ruta_recurso):
    fichero = os.path.basename(ruta_recurso)                        # Nos devuelve el nombre en forma: (nombre.extensión)
    componentes_fichero = fichero.split(".")                        # Obtenemos una lista de la forma: (nombre, extensión)
    extension_fichero = componentes_fichero[1]                      # Nos quedamos con la extensión del fichero
    return extension_fichero


def headers_response_comunes(codigo_resp, mensaje_resp, extension, tam_body):
    """Define las cabeceras de la respuesta HTTP comunes tanto para un mensaje de error como de OK"""
    
    response = VERSION + " " + codigo_resp + " " + mensaje_resp + "\r\n"
    response = response + "Server: " + SERVER_NAME + "\r\n"
    response = response + "Content-Type: " + filetypes[extension] + "\r\n"
    response = response + "Content-Length: " + str(tam_body) + "\r\n"
    response = response + "Date: " + datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT') + "\r\n"
    response = response + "Connection: " + "Keep-Alive" + "\r\n"
    response = response + "Keep-Alive: " + "timeout=" + str(TIMEOUT_CONNECTION)+ ", " + "max=" + str(MAX_ACCESOS) + "\r\n"
    
    return response


def create_response_error(error_code, error_message, recurso_body):
    """Enviar una respuesta de error"""
    
    # Leer el body, sacar su tamaño y su extensión
    tam_recurso_body = os.stat(recurso_body).st_size
    body = leer_recurso(recurso_body)
    extension_body = obtener_extension(recurso_body)
    
    # Crear la respuesta
    response = headers_response_comunes(error_code, error_message, extension_body, tam_recurso_body)
    response = response + "\r\n"
    
    respuesta = response.encode() + body        # Dado que el cuerpo de la respuesta está en bytes, debemos convertir la línea de petición y cabeceras a bytes
    return respuesta
    

def create_response_ok(metodo, extension, cookie_counter, body, tam_body, linea_peticion):
    """Enviar una respuesta de OK a la petición"""
    response = headers_response_comunes(ACCEPT_CODE, ACCEPT_MESSAGE, extension, tam_body)
    
    # Si el recurso pedido es /index.html debemos añadir la cabecera cookie
    if ( (metodo == "GET") and (linea_peticion[URL] == "/") ):
        # En Set-Cookie hay que poner cookie_counter_1740
        response = response + "Set-Cookie: " + NOMBRE_COOKIE + "=" + str(cookie_counter) + " " + "Max-Age=" + str(EXPIRE_TIME) + "\r\n"
    
    response = response + "\r\n"
    respuesta = response.encode() + body        # Dado que el cuerpo de la respuesta está en bytes, debemos convertir la línea de petición y cabeceras a bytes
    return respuesta    


def send_response (cs, response):
    """Enviar una respuesta HTTP por el socket"""
    # Bucle para enviar la respuesta por el socket
    tam_response = len(response)                                           # len devuelve el nº de caracteres de la cadena, como cada carácter es 1 byte
                                                                           # nos devuelve el tamaño en bytes de la respuesta
    tam_enviado = 0
    while (tam_enviado < tam_response):
        num_bytes_snd = enviar_mensaje(cs, response[tam_enviado:])         # Envío desde tam_enviado al final de los datos (funcionalidad de los strings)
        tam_enviado = tam_enviado + num_bytes_snd
       

def process_web_request(cs, webroot):
    """ Procesamiento principal de los mensajes recibidos.
        Típicamente se seguirá un procedimiento similar al siguiente (aunque el alumno puede modificarlo si lo desea)

        * Bucle para esperar hasta que lleguen datos en la red a través del socket cs con select()

            * Se comprueba si hay que cerrar la conexión por exceder TIMEOUT_CONNECTION segundos
              sin recibir ningún mensaje o hay datos. Se utiliza select.select

            * Si no es por timeout y hay datos en el socket cs.
                * Leer los datos con recv.
                * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1                    -> Lo restringe la ER de línea de petición
                    * Devuelve una lista con los atributos de las cabeceras.                                            -> Lo obtenemos con split_message
                    * Comprobar si la versión de HTTP es 1.1                                                            -> Lo restringe la ER de línea de petición
                    * Comprobar si es un método GET o POST. Si no devolver un error Error 405 "Method Not Allowed".     -> Lo comprobamos con is_valid_method
                    * Leer URL y eliminar parámetros si los hubiera.                                                    -> Lo restringe la ER de línea de petición 
                                                                                                                           y elimina los parámetros (si los hubiese) 
                    * Comprobar si el recurso solicitado es /, En ese caso el recurso es index.html                     -> Lo comprobamos en get_ruta_recurso
                    * Construir la ruta absoluta del recurso (webroot + recurso solicitado)                             -> Lo comprobamos en get_ruta_recurso
                    * Comprobar que el recurso (fichero) existe, si no devolver Error 404 "Not found"                   -> Lo comprobamos con os.path.isfile(x)
                    * Analizar las cabeceras. Imprimir cada cabecera y su valor. Si la cabecera es Cookie comprobar     -> Lo hacemos en el logger.info
                      el valor de cookie_counter para ver si ha llegado a MAX_ACCESOS.
                      Si se ha llegado a MAX_ACCESOS devolver un Error "403 Forbidden"
                    * Obtener el tamaño del recurso en bytes.                                                           -> Lo hacemos con os.stat(x).st_size
                    * Extraer extensión para obtener el tipo de archivo. Necesario para la cabecera Content-Type        -> Lo hacemos con os.path.basename(x)
                    * Preparar respuesta con código 200. Construir una respuesta que incluya: la línea de respuesta y   -> Lo hacemos con create_response_ok
                      las cabeceras Date, Server, Connection, Set-Cookie (para la cookie cookie_counter),
                      Content-Length y Content-Type.
                    * Leer y enviar el contenido del fichero a retornar en el cuerpo de la respuesta.                   -> Lo hacemos con leer_recurso
                    * Se abre el fichero en modo lectura y modo binario
                        * Se lee el fichero en bloques de BUFSIZE bytes (8KB)
                        * Cuando ya no hay más información para leer, se corta el bucle

            * Si es por timeout, se cierra el socket tras el período de persistencia.
                * NOTA: Si hay algún error, enviar una respuesta de error con una pequeña página HTML que informe del error.
    """
    num_peticiones = 0
    while (num_peticiones < MAX_PETICIONES):
        (rlist, wlist, xlist) = select.select([cs],[],[], TIMEOUT_CONNECTION)
        
        if (not rlist):
            logger.info("Se ha excedido el timeout de espera para recibir una solicitud")
            cerrar_conexion(cs)
            sys.exit()
        else:
            num_peticiones = num_peticiones + 1
            logger.info("Nueva petición al servidor. Número de petición: {}".format(num_peticiones))
            
            datos = recibir_mensaje(cs)
            (linea_peticion, headers, body) = split_message(datos)
            
            if (linea_peticion):
                print(f"\nLínea de petición de la solicitud: {linea_peticion[METODO]} {linea_peticion[URL]} {linea_peticion[VERSION]}")
            
            if (not is_HTTP_correct(linea_peticion)):
                """Enviar un 400"""
                logger.error("No se ha hecho una petición con el formato de línea de petición adecuado: Método + URL + HTTP/1.1")
                ruta_recurso = webroot + "error_400.html"
                response = create_response_error(ERROR_CODE_400, ERROR_MESSAGE_400, ruta_recurso)
                send_response(cs, response)
                continue
            
            if (not is_valid_method(linea_peticion, body)):
                """Enviar un 405"""
                logger.error("El método utilizado ({}) no es válido, debe ser GET o POST".format(linea_peticion[METODO]))
                ruta_recurso = webroot + "error_405.html"
                response = create_response_error(ERROR_CODE_405, ERROR_MESSAGE_405, ruta_recurso)
                send_response(cs, response)
                continue
                
            url = linea_peticion[URL]
            ruta_recurso = get_ruta_recurso(linea_peticion, webroot)
            
            # Comprobamos que el recurso solicitado existe
            if (not os.path.isfile(ruta_recurso)):
                """Enviar un 404"""
                logger.error("El recurso solicitado {} no existe".format(ruta_recurso))
                ruta_recurso = webroot + "error_404.html"
                response = create_response_error(ERROR_CODE_404, ERROR_MESSAGE_404, ruta_recurso)
                send_response(cs, response)
                continue
            
            # Comprobamos que en la petición se ha incluido la cabecera Host
            if ("Host" in headers):
                print("\nSe ha incluido la cabecera Host en la petición")
            else:
                print("\nNo se ha incluido la cabecera Host en la petición")
            
            # Mostrar las cabeceras de la solicitud
            print("\nLas cabeceras enviadas en la solicitud son:")
            for cabecera in headers:
                print(f"{cabecera}: {headers[cabecera]}")                      # La opción f dentro del print permite escribir variables dentro de una cadena de una forma más cómoda
            print()
                
            # Distinguimos entre métodos GET y POST ya que si es GET hay que procesar las cookies
            if ( (linea_peticion[METODO] == "GET") and (ruta_recurso == webroot + "index.html") ):
                cookie_counter = process_cookies(headers, cs)
                
                if (cookie_counter == MAX_ACCESOS):
                    """Enviar un 403"""
                    logger.error("Se ha excedido el número máximo de accesos ({}) al recurso index.html, debe esperar".format(MAX_ACCESOS))
                    ruta_recurso = webroot + "error_404.html"
                    response = create_response_error(ERROR_CODE_403, ERROR_MESSAGE_403, ruta_recurso)
                    send_response(cs, response)
                    continue
            
            # Si el método es POST simpplemente hay que comprobar si el formulario ha sido relleno con un email válido. Sea cual sea el caso actuar en consecuencia
            # En nuestro caso, modificaremos la variable ruta_recurso, para que sea la dirección de una página que se corresponda a email_correcto o fallido.
            # Así interpretaremos que, aunque no se ha pedido un recurso, como hay que devolver uno de nuestros recursos, y por tanto hay que leerlo, 
            if (linea_peticion[METODO] == "POST"):
                email = get_email(body)
                
                if email:
                    print("\nEmail indicado en el formulario: {}".format(email))
                
                if email in valid_emails:
                    ruta_recurso = webroot + "email_correcto.html"
                else:
                    logger.error("El email indicado ({}) no tiene autorización".format(email))
                    ruta_recurso = webroot + "error_401.html"
                    response = create_response_error(ERROR_CODE_401, ERROR_MESSAGE_401, ruta_recurso)
                    send_response(cs, response)
                    continue
                    
            # Calcular tamaño del fichero y extensión del que debemos leer
            tam_fichero = os.stat(ruta_recurso).st_size  
            extension_fichero = obtener_extension(ruta_recurso)                           
            
            # Leemos el recurso que debe aparecer en la respuesta
            body_response = leer_recurso(ruta_recurso)
                    
            # Crear respuesta
            response = create_response_ok(linea_peticion[METODO], extension_fichero, cookie_counter, body_response, tam_fichero, linea_peticion)
    
            # Enviar respuesta
            send_response(cs, response)
            logger.info("Respuesta a la solicitud enviada")
    
    logger.info("Se ha excedido el nº máximo de solicitudes: {}".format(MAX_ACCESOS))                
    cerrar_conexion(cs)
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


        if args.verbose:
            logger.setLevel(logging.DEBUG)

        logger.info('Enabling server in address {} and port {}.'.format(args.host, args.port))
        logger.info("Serving files from {}".format(args.webroot))
        print("\nComenzamos a tratar HTTP Requests\n")
        
        """ Funcionalidad a realizar
        * Crea un socket TCP (SOCK_STREAM)
        
        * Permite reusar la misma dirección previamente vinculada a otro proceso. Debe ir antes de sock.bind
        * Vinculamos el socket a una IP y puerto elegidos

        * Escucha conexiones entrantes

        * Bucle infinito para mantener el servidor activo indefinidamente
            - Aceptamos la conexión

            - Creamos un proceso hijo

            - Si es el proceso hijo se cierra el socket del padre y procesar la petición con process_web_request()

            - Si es el proceso padre cerrar el socket que gestiona el hijo.
        """
                
        # Usaremos una estructura with. Su funcionamiento se basa en: hay cierto código que se debe ejecutar siempre. Por ello, para librar de esta tarea
        # al programador, usamos esta estructura, la cual lo ejecutará siempre por nosostros independientemente de lo que ocurra, incluso si se produce una 
        # excepción. En el caso concreto de un socket, podremos evitar tener que cerrarlo, la estructura with lo hará por nosotros
               
        # family = AF_INET   -> Socket de internet ipv4
        # type = SOCK_STREAM -> Socket TCP
        # proto = 0          -> Para las tareas que necesitaremos
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto = 0) as server_sock:         # Creamos el socket           
            
            # Podemos dar un valor a las opciones del socket, pero estas deben asignarse siempre antes de hacer el .bind, es decir, antes de enlazar el socket a un
            # puerto y una dirección IP. En nuestro caso, vamos a usar la opción socket.SO_REUSEADDR para permitir reusar una dirección IP que previamente fue
            # asignada a otro proceso. Esto es: cuando un servidor cierra una conexión, deja de poder ser utilizado el puerto de la conexión durandte un tiempo 
            # (2 o más minutos, depende del SO), para asegurar que los paquetes retrasados no se entregan a aplicaciones incorrectas. Sin embargo, esto se puede
            # obviar usando esta opción, permitiendo una nueva conexión en ese puerto de forma instantánea.
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)         
                    
            status = server_sock.bind((args.host, args.port))                                      # Vinculamos el socket al par (ip, puerto) adecuado
            
            # Comprobamos si hubo un error al tratar de enlazar el socke a un par (ip, puerto) concreto
            if (status == -1):
                logger.error("Error al tratar de establecer la conexión")
                sys.exit(1)                                                                        # Finalizamos el programa con un error
            
            server_sock.listen()                                                                   # Ponemos el socket a escuchar conexiones entrante
            
            # Creamos un bucle infinito para estar escuchando de forma indefinida 
            while (True):
                # Destacar que el .accept es bloqueante, es decir, no avanzamos hasta recibir una conexión
                (client_sock, client_addr) = server_sock.accept()                                  # Aceptamos una conexión y devolvemos: 
                                                                                                   # sock = socket nuevo que se usará para recibir los datos del 
                                                                                                   #        cliente en esta nueva conexión
                                                                                                   # addr = dirección del cliente que se ha conectado
                
                # Por tanto, es importante distiguir que: conn es el socket de comunicación con un cliente y sock es el socket para escuchar conexiones
                                                                                                
                logger.info("New connection from: {}".format(client_addr))                         # Imprimimos la dirección IP del cliente que se ha conectado
            
                # Creamos un proceso hijo
                pid = os.fork() 

                if (pid == -1):
                    logger.error("Error al crear un hijo")
                elif (pid == 0):                                                                   # Pid = 0 <-> proceso hijo
                    cerrar_conexion(server_sock)                                                   # Cerramos este socket pues solo lo usa el padre
                    
                    logger.info('Processing message from {}'.format(client_addr))
                    process_web_request(client_sock, args.webroot)                                 # Procesamos la petición
                else:                                                                              # Estamos en el proceso padre
                    cerrar_conexion(client_sock)                                                   # Cerramos este socket pues solo lo usa el hijo
                                                                                                                                                                             
    except KeyboardInterrupt:
        True

if __name__== "__main__":
    main()
