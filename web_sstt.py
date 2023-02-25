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
TIMEOUT_CONNECTION = 60                                                 # Timout para la conexión persistente: 1 + 7 + 4 + 0 + 20 = 22
MAX_ACCESOS = 10                                                        # Nº máximo de accesos al recurso index.html
MAX_PETICIONES = 30                                                     # Nº máximo de peticiones del cliente al servidor
MIN_COOKIE_VALUE = 1                                                    # Valor mínimo de un cookie-counter
NO_VALID_VALUE = 0                                                      # Valor no válido de la cookie
CLOSE_CONNECTION = 1                                                    # Valor para indicar que cuando excedamos las 10 peticiones al index.html hay que enviar un
                                                                        # close en la respuesta

# Terna de valores para acceder al diccionario que contiene la línea de petición (método usado, recurso solicitado, versión HTTP)
METODO = "method"
URL = "url"
VERSION = "version"

# Código a devolver cuando la solicitud del cliente es correctas
ACCEPT_CODE = "200 OK"

# Códigos a devolver cuando la solicitud del cliente es incorrecta
ERROR_MESSAGE_400 = "400 Bad Request"
ERROR_MESSAGE_401 = "401 Unauthorized"
ERROR_MESSAGE_403 = "403 Forbidden"
ERROR_MESSAGE_404 = "404 Not Found"
ERROR_MESSAGE_405 = "405 Method Not Allowed"

# Nombre del servidor
SERVER_NAME = "web.ceronaturalistas1740.org"

# Valores que deben tomar los campos de la cookie en la respuesta
NOMBRE_COOKIE = "cookie_counter_1740"
EXPIRE_TIME = "120"                                                   # 2 minutos = 120 segundos (unidad que se debe indicar en Max-Age)

# Tipo de fichero por defecto
TYPE_FICH_DEF = "text/plain"

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js", "mp4":"video/mp4", "ogg":"audio/ogg", "ico":"image/ico","mp3":"audio/mpeg"}

# Correos válidos para el formulario a rellenar
valid_emails = ["ja.lopezsola%40um.es", "f.uclesayllon%40um.es"]      # El @ se decodifica como un %40

# Cabeceras a enviar en respuesta
headers = {"vers":"HTTP/1.1 {}\r\n", "server":"Server: {}\r\n", "cont-ty":"Content-Type: {}\r\n", "cont-lng":"Content-Length: {}\r\n",
           "date":"Date: {}\r\n", "conn":"Connection: {}\r\n", "cookie":"Set-Cookie: {}={}; Max-Age={}\r\n", "keep":"Keep-Alive: timeout={}, max={}\r\n"}

html = {"index":"/index.html", "mail":"/accion_form.html", "400":"/Errores/error_400.html", "401":"/Errores/error_401.html", "403":"/Errores/error_403.html",
        "404":"/Errores/error_404.html","405":"/Errores/error_405.html",}

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
        logger.error("Error al tratar de enviar datos por el socket, cerramos la conexión")  
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
        logger.error("Error al tratar de recibir datos por el socket, cerramos la conexión")  
        cerrar_conexion(cs)
        sys.exit(1)
    
    return datos_rcv.decode()                                           # Devolvemos los datos recibidos del socket convertidos a string
    
    # pass                                                              # Se utiliza cuando las funciones están vacías para que no de errores


def process_cookies(headers):
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
                return NO_VALID_VALUE
            
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
        ruta_recurso = webroot + html["index"]
    else:
        ruta_recurso = webroot + url                           
    
    return ruta_recurso
    

def get_email(body):
    """Obtener el email del formulario que se ha rellenado"""
    patron_email = r'(?<=email=).+(?=(&| |\r\n|))'            # Le añado la posibilidad de que el body no acabe en nada más además de la cadena, es decir, ni
                                                              # \r\n ni espacio ni & ni nada, el vacío solamente
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


def headers_response_comunes(codigo_resp, extension, tam_body, num_pet, close = 0):
    """Define las cabeceras de la respuesta HTTP comunes tanto para un mensaje de error como de OK"""
    # Si la extensión no está en nuestro diccionario, devolvermos una por defecto: text/plain
    type_fich = filetypes[extension]
    
    if (not type_fich):
        type_fich = TYPE_FICH_DEF
    
    # Construimos el mensaje
    response = (headers["vers"].format(codigo_resp) + headers["server"].format(SERVER_NAME) + headers["cont-ty"].format(type_fich) 
                + headers["cont-lng"].format(str(tam_body)) + headers["date"].format(datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')) )
      
    if (close == 0):
        response = response + headers["conn"].format("Keep-Alive") 
        # Solo enviamos las condiciones de keep-alive la primera vez
        if (num_pet == 1):
            response = response + headers["keep"]. format(str(TIMEOUT_CONNECTION), str(MAX_PETICIONES))
    else:
        response = response + headers["conn"].format("close")
    
    return response


def create_response_error(error_message, recurso_body, num_pet, close = 0):
    """Enviar una respuesta de error"""
    
    # Leer el body, sacar su tamaño y su extensión
    tam_recurso_body = os.stat(recurso_body).st_size
    body = leer_recurso(recurso_body)
    extension_body = obtener_extension(recurso_body)
    
    # Crear la respuesta
    response = headers_response_comunes(error_message, extension_body, tam_recurso_body, num_pet, close)
    response = response + "\r\n"
    
    respuesta = response.encode() + body        # Dado que el cuerpo de la respuesta está en bytes, debemos convertir la línea de petición y cabeceras a bytes
    return respuesta
    

def create_response_ok(linea_peticion, extension, cookie_counter, body, tam_body, num_pet):
    """Enviar una respuesta de OK a la petición"""
    response = headers_response_comunes(ACCEPT_CODE, extension, tam_body, num_pet)
    
    # Si el recurso pedido es /index.html debemos añadir la cabecera cookie
    if ( (linea_peticion[METODO] == "GET") and (linea_peticion[URL] == "/") ):
        # En Set-Cookie hay que poner cookie_counter_1740 y Max-Age solo se envía si es pertinente (no hay que enviarlo constantemente o la cookie no expirará)
        response = response + headers["cookie"].format(NOMBRE_COOKIE, str(cookie_counter), EXPIRE_TIME)
    
    response = response + "\r\n"
    respuesta = response.encode() + body        # Dado que el cuerpo de la respuesta está en bytes, debemos convertir la línea de petición y cabeceras a bytes
    return respuesta    


def send_response (cs, response):
    """Enviar una respuesta HTTP por el socket"""
    # Bucle para enviar la respuesta por el socket
    tam_response = len(response)                                           # len devuelve el nº de bytes de la cadena                                                                      # nos devuelve el tamaño en bytes de la respuesta
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
                * Analizar que la línea de solicitud y comprobar está bien formateada según HTTP 1.1            dsfsf        -> Lo restringe la ER de línea de petición
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
    # Inicializamos el valor de la cookie a no válido para evitar posibles llamadas a send_response sin haber creado el cookie counter aun. 
    # Esto ocurre si se cierra la conexión, pero el cliente se ha quedado con la web abierte, cuando meta un correo, al ser un post no se origina la variable
    # cookie_counter en el nuevo hijo que se encarga de las peticiones, por tanto podría producirse una excepción por un uso de variable no inicializado
    cookie_counter = NO_VALID_VALUE   
    
    # Contador para el nº de peticiones realizadas al servidor desde esta conexión 
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
                ruta_recurso = webroot + html["400"]
                response = create_response_error(ERROR_MESSAGE_400, ruta_recurso, num_peticiones)
                send_response(cs, response)
                continue
            
            if (not is_valid_method(linea_peticion, body)):
                """Enviar un 405"""
                logger.error("El método utilizado ({}) no es válido, debe ser GET o POST".format(linea_peticion[METODO]))
                ruta_recurso = webroot + html["405"]
                response = create_response_error(ERROR_MESSAGE_405, ruta_recurso, num_peticiones)
                send_response(cs, response)
                continue
                
            url = linea_peticion[URL]
            ruta_recurso = get_ruta_recurso(linea_peticion, webroot)
            
            # Comprobamos que el recurso solicitado existe
            if (not os.path.isfile(ruta_recurso)):
                """Enviar un 404"""
                logger.error("El recurso solicitado {} no existe".format(ruta_recurso))
                ruta_recurso = webroot + html["404"]
                response = create_response_error(ERROR_MESSAGE_404, ruta_recurso, num_peticiones)
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
                # La opción f dentro del print permite escribir variables dentro de una cadena de una forma más cómoda
                print(f"{cabecera}: {headers[cabecera]}")                 
            print()
                
            # Distinguimos entre métodos GET y POST ya que si es GET hay que procesar las cookies
            if ( (linea_peticion[METODO] == "GET") and (ruta_recurso == (webroot + html["index"]))):
                cookie_counter = process_cookies(headers)
                
                if (cookie_counter == NO_VALID_VALUE):
                    """Enviar un 403"""
                    logger.info("Se ha excedido el número máximo de accesos ({}) al recurso index.html, debe esperar 2 "
                                "minutos desde su última petición. Cerraremos la conexión mientras tanto".format(MAX_ACCESOS))
                    ruta_recurso = webroot + html["403"]
                    response = create_response_error(ERROR_MESSAGE_403, ruta_recurso, num_peticiones, CLOSE_CONNECTION)
                    send_response(cs, response)
                    cerrar_conexion(cs)
                    sys.exit()
            
            # Si el método es POST simpplemente hay que comprobar si el formulario ha sido relleno con un email válido. Sea cual sea el caso actuar en consecuencia
            # En nuestro caso, modificaremos la variable ruta_recurso, para que sea la dirección de una página que se corresponda a email_correcto o fallido.
            # Así interpretaremos que, aunque no se ha pedido un recurso, como hay que devolver uno de nuestros recursos, y por tanto hay que leerlo, 
            if (linea_peticion[METODO] == "POST"):
                email = get_email(body)
                
                if email:
                    print("\nEmail indicado en el formulario: {}".format(email))
                
                if email in valid_emails:
                    ruta_recurso = webroot + html["mail"]
                else:
                    """Enviar un 401"""
                    logger.error("El email indicado ({}) no tiene autorización".format(email))
                    ruta_recurso = webroot + html["401"] 
                    response = create_response_error(ERROR_MESSAGE_401, ruta_recurso, num_peticiones)
                    send_response(cs, response)
                    continue
                    
            # Calcular tamaño del fichero y extensión del que debemos leer
            tam_fichero = os.stat(ruta_recurso).st_size  
            extension_fichero = obtener_extension(ruta_recurso)                           
            
            # Leemos el recurso que debe aparecer en la respuesta
            body_response = leer_recurso(ruta_recurso)
                    
            # Crear respuesta
            response = create_response_ok(linea_peticion, extension_fichero, cookie_counter, body_response, tam_fichero, num_peticiones)
    
            # Enviar respuesta
            send_response(cs, response)
            logger.info("Respuesta a la solicitud enviada")
    
    logger.info("Se ha excedido el nº máximo de solicitudes: {}. Cerramos la conexión".format(MAX_PETICIONES))                
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
            
        # Comprobamos si se ha pasado como webroot una estructura de la forma: /../../ y en ese caso quitamos el último /
        if (args.webroot[len(args.webroot)-1] == "/"):
            args.webroot = args.webroot[:len(args.webroot)-1]

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
