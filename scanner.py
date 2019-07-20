import socket
import click
import threading
import time
from type_utilities import *


class PortScanner:
	"""Scanner class"""

	class ScanResult:
		"""Scan Result class"""

		# Result Possibilities
		OPEN = 'open'
		FILTERED = 'filtered'
		CLOSED = 'closed'

		def __init__(self, port, message, status):
			self.port = port
			self.message = message
			self.status = status

		def is_open(self):
			return self.status == PortScanner.ScanResult.OPEN

		def __str__(self):
			return f'{self.port}\t\t{self.status}\t\t{self.message}'

	def __init__(self, ip, port_range, protocol, thread_count=1, timeout_sleep=0.5):
		self.scan_results = []

		self.thread_count = thread_count
		self.port_range = port_range
		self.timeout_sleep = timeout_sleep
		self.ip = ip
		self.protocol = protocol
		self.threads = []

		self.scan_results_lock = threading.Lock()
		self.port_range_lock = threading.Lock()

	def __iter__(self):
		return self

	def __next__(self):
		if self.is_done():
			raise StopIteration

		while True:
			while not self.scan_results:
				time.sleep(self.timeout_sleep)
			with self.scan_results_lock:
				if self.scan_results:
					return self.scan_results.pop(0)

	def _start_scanner(self):
		while True:
			time.sleep(self.timeout_sleep)
			try:
				next_port = self.next_port()						# Next port to scan

				s = socket.socket(socket.AF_INET, self.protocol)  	# Create new socket
				s.connect((self.ip, next_port))  					# connect to host on specified port
				self.add_scan_result(
					PortScanner.ScanResult(
						next_port,
						'Port is up',
						PortScanner.ScanResult.OPEN
					)
				)
			except StopIteration:									# All ports scanned
				break
			except Exception as err:
				messages = {
					ConnectionRefusedError: 'Port seems closed',
					TimeoutError: 'Connection timed out',
					OSError: f'OS threw an error while scanning this port, error message:\n\t"{err}"',
				}

				s.close()
				self.add_scan_result(
					PortScanner.ScanResult(
						next_port,
						messages.get(type(err)) or err,
						PortScanner.ScanResult.CLOSED
					)
				)

	def next_port(self):
		return next(self.port_range)

	def is_done(self):
		with self.scan_results_lock:
			if self.scan_results:
				return False
		for thread in self.threads:
			if thread.is_alive():
				return False
		return True

	def start_scanner(self):
		for _ in range(self.thread_count):							# Start n threads for faster processing
			thread = threading.Thread(
				target=self._start_scanner,
				daemon=True
			)
			thread.start()
			self.threads.append(thread)

	def add_scan_result(self, result):
		with self.scan_results_lock:
			self.scan_results.append(result)


@click.command()
@click.argument('ip', type=IpOrHostName(), required=True)
@click.option('-t', '--tcp', help='Toggle TCP Scan', type=bool, default=True, is_flag=True)
@click.option('-u', '--udp', help='Toggle UDP Scan', type=bool, default=False, is_flag=True)
@click.option('-T', '--thread-count', help='Number of threads', type=int, default=1)
@click.option('-s', '--timeout', help='Amount of time to sleep between successive port scans', type=float, default=0.5)
@click.option('-o', '--open', help='Print only open ports', type=bool, default=False, is_flag=True)
@click.option('-p', '--port-range', help='Port range(\'-\' separated)/list(\',\' separated)', type=PortRange(), required=True)
def scan(ip, tcp, udp, port_range, thread_count, timeout, open):
	if tcp and udp:
		click.echo('Please specify a single protocol!')
		exit(0)

	protocol = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
	open_only = open
	scanner = PortScanner(
		ip,
		port_range,
		protocol,
		thread_count=thread_count,
		timeout_sleep=timeout
	)
	scanner.start_scanner()
	result_itr = iter(scanner)
	while True:
		try:
			next_result = next(result_itr)
			if open_only:
				if next_result.is_open():
					print(next_result)
			else:
				print(next_result)
		except StopIteration:
			break


if __name__ == '__main__':
	scan()
