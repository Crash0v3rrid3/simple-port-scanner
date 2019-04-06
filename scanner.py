import socket
import sys
import re

if len(sys.argv) < 4:
	print('''Usage: {} protocol ip port/s
Examples:
{} tcp 192.168.1.11 80,100
{} udp 1.1.1.1 53
{} tcp www.google.com 50-100 '''.format(sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0]))	# Check if the arguments are correct
	exit(1)

protocol = sys.argv[1]
ip = sys.argv[2]
ports = sys.argv[3]
match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip)	# Chech to see if IP Specified
if None == match:
	try: 
		ip = socket.gethostbyname(ip)	# Get the ip from the host name
	except socket.gaierror: 			# Exception raised if hostname not reachable
		print("There was an error resolving the host!\n Exiting Now...")	# Exit on exception
		exit(1)

if protocol == 'tcp':	# set the protocol
	protocol = socket.SOCK_STREAM
elif protocol == 'udp':
	protocol = socket.SOCK_DGRAM
else:
	print("Invalid Protocol!\nExiting Now...")	# If not udp or tcp, exit
	exit(1)

try:
	if('-' in ports):
		ports = list(range(*list(map(int, ports.split('-')))))	# Format the ports based on -
	elif(',' in ports):
		ports = list(map(int, ports.split(',')))	# Format the ports based on ,
except:
	print('Invalid Ports Specified!')
	exit(1)

if type(ports) != type([]):
	ports = [int(ports)]

if len(list(filter(lambda x: x > 65535, ports))) > 0:	# Check if any invalid ports specified
	print('Invalid Ports Specified!')
	exit(1)

for port in ports:
	s = socket.socket(socket.AF_INET, protocol) # Create new socket
	try:
		s.connect((ip, port))		# connect to host on specified port
	except ConnectionRefusedError:
		print("{}:{} Connection refused".format(ip, port)) # if exception raised, host ip not reachable
		continue
	print("{}:{} Port Open".format(ip, port))	# Else reachable
	s.close()