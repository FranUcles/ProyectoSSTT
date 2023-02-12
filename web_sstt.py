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
TIMEOUT_CONNECTION = 20                                     # Timout para la conexión persistente
MAX_ACCESOS = 10

MIN_COOKIE_VALUE = 1                                        # Valor mínimo de un cookie-counter

# Extensiones admitidas (extension, name in HTTP)
filetypes = {"gif":"image/gif", "jpg":"image/jpg", "jpeg":"image/jpeg", "png":"image/png", "htm":"text/htm", 
             "html":"text/html", "css":"text/css", "js":"text/js"}

# Configuración de logging
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s.%(msecs)03d] [%(levelname)-7s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()


def enviar_mensaje(cs, data):
    """ Esta función envía datos (data) a través del socket cs
        Devuelve el número de bytes enviados.
    """
    bytes_snd = cs.send(data.encode)                        # Codificamos los datos que tenemos en forma de string para poder enviarlos por el socket
    return bytes_snd                                        # Devolvemos el nº de bytes enviados



def recibir_mensaje(cs):
    """ Esta función recibe datos a través del socket cs
        Leemos la información que nos llega. recv() devuelve un string con los datos.
    """
    datos_rcv = cs.recv(BUFSIZE)                            # Lee los datos que se encuentran en el socket
    return datos_rcv.decode                                 # Devolvemos los datos recibidos del socket convertidos a string
    
    # pass                                                  # Se utiliza cuando las funciones están vacías para que no de errores


def cerrar_conexion(cs):
    """ Esta función cierra una conexión activa.
    """
    cs.close()                                              # Permite cerrar la conexión que establece el socket


def process_cookies(headers,  cs):
    """ Esta función procesa la cookie cookie_counter
        1. Se analizan las cabeceras en headers para buscar la cabecera Cookie
        2. Una vez encontrada una cabecera Cookie se comprueba si el valor es cookie_counter
        3. Si no se encuentra cookie_counter , se devuelve 1
        4. Si se encuentra y tiene el valor MAX_ACCESSOS se devuelve MAX_ACCESOS
        5. Si se encuentra y tiene un valor 1 <= x < MAX_ACCESOS se incrementa en 1 y se devuelve el valor
    """
    patron_cookie = r'Cookie.+'                             # Patrón para obtener la línea de cabecera asociada a la cookie
    er_cookie = re.compile(patron_cookie)                   # Compilamos la ER
    match_cookie = er_cookie.search(headers)                # Buscamos la línea de cabecera cookie:
    
    if (match_cookie):
        header_cookie = headers[match_cookie.start():match_cookie.end()]       # Nos quedamos con el string perteneciente a la línea de cabecera cookie
        
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
                    * Comprobar si es un método GET. Si no devolver un error Error 405 "Method Not Allowed".
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
                
        # Si usamos una estructura with, podemos tener una estructura similar a un try, catch, finally: hay cierto código que se ejecutará siempre
        # independientemente de lo que ocurra, incluso si se produce una excepción. En el caso concreto de un socket, podríamos evitar tener que cerrarlo
        # la estructura with lo haría por nosotros
        # Un ejemplo de uso es:
        """
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto = 0) as sock:           
                sock.bind((args.host, args.port))  
                sock.listen()
                
                conn, addr = sock.accept()
                
                print(f"Connected by {addr}")           # La opción f dentro del print permite escribir variables dentro de una cadena de una forma más cómoda
            
                while (True):
                    data = conn.recv(BUFSIZE)
                    
                    if not data:
                        break
                        
                    conn.sendall(data) 
        """
        
        # family = AF_INET -> Socket de internet ipv4
        # type = SOCK_STREAM -> Socket TCP
        # proto = 0 -> Para las tareas que necesitaremos
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto = 0)           # Creamos el socket  
        
        # Podemos dar un valor a las opciones del socket, pero estas deben asignarse siempre antes de hacer el .bind, es decir, antes de enlazar el socket a un
        # puerto y una dirección IP. En nuestro caso, vamos a usar la opción socket.SO_REUSEADDR para permitir reusar una dirección IP que previamente fue
        # asignada a otro proceso. Esto es: cuando un servidor cierra una conexión, deja de poder ser utilizado el puerto de la conexión durandte un tiempo 
        # (2 o más minutos, depende del SO), para asegurar que los paquetes retrasados no se entregan a aplicaciones incorrectas. Sin embargo, esto se puede
        # obviar usando esta opción, permitiendo una nueva conexión en ese puerto de forma instantánea.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)         
                   
        status = sock.bind((args.host, args.port))                                             # Vinculamos el socket al par (ip, puerto) adecuado
        
        # Comprobamos si hubo un error al tratar de enlazar el socke a un par (ip, puerto) concreto
        if (status == -1):
            logging.error("Error al tratar de establecer la conexión")
            sys.exit(1)                                                                        # Finalizamos el programa con un error
        
        sock.listen()                                                                          # Ponemos el socket a escuchar conexiones entrantes
        
        # Creamos un bucle infinito para estar escuchando de forma indefinida 
        while (True):
            # Destacar que el .accept es bloqueante, es decir, no avanzamos hasta recibir una conexión
            (conn, addr) = sock.accept()                                                       # Aceptamos una conexión y devolvemos: 
                                                                                               # conn = socket nuevo que se usará para recibir los datos del 
                                                                                               #        cliente en esta nueva conexión
                                                                                               # addr = dirección del cliente que se ha conectado
            
            # Por tanto, es importante distiguir que: conn es el socket de comunicación con un cliente y sock es el socket para escuchar conexiones
                                                                                               
            logging.info("New connection from: {addr}")                                        # Imprimimos la dirección IP del cliente que se ha conectado
        
            # Creamos un proceso hijo
            pid = os.fork() 
        
            if (pid == 0):                                                                     # Pid = 0 <-> proceso hijo
                cerrar_conexion(sock)                                                          # Cerramos este socket pues solo lo usa el padre
                process_web_request(conn, args.webroot)                                        # Procesamos la petición
            else:                                                                              # Estamos en el proceso padre
                cerrar_conexion(conn)                                                          # Cerramos este socket pues solo lo usa el hijo
                                                                                                                                                                             
    except KeyboardInterrupt:
        True

if __name__== "__main__":
    main()
