'''
    ip.py
    
    Funciones necesarias para implementar el nivel IP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    y = 0x27af    
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    y = y & 0x00ff
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
   
    s.close()
   
    return mtu
   
def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum y comprobar que es correcto                    
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -TTL
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                    pasando los datos (payload) contenidos en el datagrama IP.
        
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    data = bytes(data)

    '''
        Versión (4 bits): Campo que indica la versión de IP. En nuestro caso será siempre 4
    IHL (4 bits): Longitud de la cabecera IP. Como la cabecera IP puede contener opciones de tamaño variable este campo nos indica el tamaño de la cabecera. Este campo está expresado en palabras de 4 bytes. Es decir, para obtener el tamaño total (en número de bytes) de la cabecera es necesario multiplicar este campo por 4. El tamaño mínimo de una cabecera IP es 20 bytes y el máximo 60.
    Type of Service (1 byte): indicador del tipo de tráfico que transporta este datagrama. Este campo sirve para priorización y marcado de tráfico. En nuestro caso siempre usaremos el valor 0x10.
    Total Length(2 Bytes): Longitud total (en número de bytes) del datagrama IP actual. Incluye tanto la cabecera como el payload que va detrás de la cabecera.
    Identification (2 Bytes): Identificador del datagrama IP (también llamado IPID). Este campo es útil cuando hay fragmentación IP. En este caso todos los fragmentos tienen el mismo valor de IPID. Para los envíos, este valor se fija inicialmente al arrancar el nivel IP de manera aleatoria . En la práctica lo fijaremos al número de pareja .
    Flags (3 bits): Banderas IP:
        Bit 1 (Reservado): siempre a 0
        Bit 2 (DF): bandera que indica que no debe fragmentarse el datagrama. En nuestro caso será siempre 0.
        Bit 3 (MF): bandera que indica que vienen más fragmentos tras el datagrama actual. En caso de fragmentar todos los fragmentos tendrán este bit a 1 menos el último fragmento.
    Offset (13 bits): campo que indica (en caso de fragmentación) el offset de los datos contenidos en el datagrama actual respecto al total de datos sin fragmentar. Está expresado en palabras de 8 bytes. Es decir, para obtener el valor real de offset se debe multiplicar este campo por 8.
    Time to Live  (1 Byte): campo que indica el número máximo de saltos IP que puede realizar el datagrama actual antes de ser descartado. Cada vez que un paquete atraviesa un salto a nivel IP se decrementa en 1 y cuando llega a 0 el datagrama actual se descarta. En nuestro caso usaremos siempre el valor por defecto 64.
    Protocol (1 Byte): Campo que indica el protocolo de nivel superior encapsulado en el payload del datagrama. Este campo tiene un cometido similar al campo Ethertype en Ethernet. Algunos valores típicos son: 1 para ICMP, 6 para TCP y 17 para UDP.
    Header Checksum (2 Bytes): suma de verificación calculada sobre la cabecera IP que sirve para detectar errores o modificaciones de la cabecera IP durante el envío de datos. Cuando recibimos un datagrama, si el cálculo de checksum es erróneo debemos descartarlo.
    Dirección IP origen (4 Bytes): dirección IP del emisor del datagrama actual
    Dirección IP destino (4 Bytes): dirección IP del receptor del datagrama
    Opciones (Tamaño variable): Opciones que aportan funcionalidades adicionales. Su tamaño tiene que ser múltiplo 4 bytes. El tamaño mínimo de opciones es 0 bytes y el máximo 40 bytes.
    '''
    version = data[0] >> 0x04

    IHL = data[0] & 0x0F
    IHL = IHL * 4

    ToS = data[1]

    TL = data[2:4]

    identification = data[4:6]

    DF = data[6] & 0x40
    DF = DF >> 6
    MF = data[6] & 0x20
    MF = MF >> 5 

    offset = int.from_bytes(data[6:8], byteorder='big') & 0x1F
    if offset is not 0:
        return

    TTL = data[8]

    protocol = data[9]

    HCK = data[10:12]

    IPO = data[12:16]
    IPD = data[16:20]

    checksum = chksum(data[:IHL])

    logging.debug("Longitud cabecera IP: "+str(IHL))
    logging.debug("ID datagrama: "+str(identification))
    logging.debug("DF: "+str(DF))
    logging.debug("MF: "+str(MF))
    logging.debug("offset: "+str(offset))
    logging.debug("IP origen: "+str(iporigen))
    logging.debug("IP destino: "+str(ipdestino))
    if protocol  == 1:
        logging.debug("Protocolo: ICMP")
    else if protocol == 6:
        logging.debug("Protocolo: IP")
    else if protocol == 17:
        logging.debug("Protocolo: UDP")
    
    if not protocol in protocols:
        logging.debug("Función no registrada")
        return

    func = protocols[protocol]
    payload = data[IHL:]
    func(us, header, payload, IPO)



def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
            (diccionario) de protocolos de nivel superior dicha asociación. 
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
            llamada process_ICMP_message asocaida al valor de protocolo 1. 
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno 
    '''
    protocols[protocol] = callback

def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
            -Inicializar el valor de IPID con el número de pareja
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''
    err = initARP(interface)
    if err is 1:
        return False

    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)
    ipOpts = opts

    registerCallback(process_IP_datagram, bytes([0x08,0x00]))

    IPID = 13

    return True


def sendIPDatagram(dstIP,data,protocol):
    global IPID
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda.Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas se debe hacer unso de la máscara de red:                  
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama 
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
          
    '''
    global subnetMask
    subnetMask = 0xFFFFFF00
    
    dstMAC = ARPResolution(dstIP & subnetMask)

    if ipOpts is not None:
        iplen = IP_MIN_HLEN + len(ipOpts)
    else:
        iplen = IP_MIN_HLEN

    if iplen > IP_MAX_HLEN:
        return False


    max_payload_size = 1500 - iplen
    while max_payload_size%8 is not 0:
        max_payload_size -= 1

    fragments_count = (len(data) + max_payload_size - 1) // max_payload_size

    for fragment_index in range(fragments_count):
        ip_header = struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(data), IPID, 0, 64, protocol, 0, 0, srcIP, dstIP)

        if fragment:
            flags_offset = (fragment_index << 13) | fragment_offset
            ip_header = struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(data), IPID, flags_offset, 64, protocol, 0, 0, srcIP, dstIP)

        checksum = chksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', checksum) + ip_header[12:]
        ip_packet = ip_header + data[fragment_index * max_payload_size: (fragment_index + 1) * max_payload_size]

        sendEthernetFrame(ip_packet, len(ip_packet), bytes([0x08, 0x00]), dstMAC)

        if not fragment:
            IPID += 1

    return True



