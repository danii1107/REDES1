'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2020 EPS-UAM
    Modificado: Daniel Aquino, Daniel Birsan
'''

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import datetime
import logging

ETH_FRAME_MAX = 1514
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60

def print_hex_bytes(data, nbytes):
	if len(data) < nbytes:
		nbytes = len(data)
	hex_bytes = " ".join([f"{byte:02X}" for byte in data[:nbytes]])
	print(f"{hex_bytes}")

def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)

def check_non_negative(value):
	ivalue=int(value)
	if ivalue < 0:
		raise argparse.ArgumentTypeError("El numero de paquetes a procesar no puede ser negativo")
	return ivalue

def procesa_paquete(us,header,data):
	global num_paquete, dumper1, dumper2
	logging.info('Nuevo paquete de {} bytes capturado en el timestamp UNIX {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_sec))
	num_paquete += 1

	header.ts.tv_sec += 2700

	if args.interface:
		if len(data) >= 14 and data[12] == 0x08 and data[13] == 0x06:
			pcap_dump(dumper1, header, data)
		else:
			pcap_dump(dumper2,  header, data)
	if args.nbytes > 0:
		print_hex_bytes(data, args.nbytes)
	
if __name__ == "__main__":
	global dumper1,args,handle, dumper2, delta
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	parser.add_argument('--npkts', dest='npkts', type=check_non_negative, default=sys.maxsize, help='Numero de paquetes a procesar')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	errbuf = bytearray()
	handle = None
	dumper1 = None
	dumper2 = None

	if args.tracefile:
		handle = pcap_open_offline(args.tracefile, errbuf)
	elif args.interface:
		handle = pcap_open_live(args.interface, ETH_FRAME_MAX, PROMISC, TO_MS, errbuf)
		tracefile_name1 = f"capturaARP.{args.interface}.{int(time.time())}.pcap"
		tracefile_name2 = f"captura.{args.interface}.{int(time.time())}.pcap"
		descr1 = descr2 = pcap_open_dead(DLT_EN10MB, 1514)
		dumper1 = pcap_dump_open(descr1, tracefile_name1)
		dumper2 = pcap_dump_open(descr2, tracefile_name2)		
	
	ret = pcap_loop(handle,args.npkts,procesa_paquete,None)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')

	logging.info('{} paquetes procesados'.format(num_paquete))

	if args.interface:
		if descr1:
			pcap_close(descr1)
		if descr2:
			pcap_close(descr2)
		if dumper1:
			pcap_dump_close(dumper1)
		if dumper2:
			pcap_dump_close(dumper2)
