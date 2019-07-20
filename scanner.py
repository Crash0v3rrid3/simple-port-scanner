import socket
import re
import click
import threading
import time


# Type utilities
class IpOrHostName(click.ParamType):

	def convert(self, value, param, ctx):
		"""Converts hostnames/domain names into IP's"""
		# Is IP given?
		match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value)

		if match is None:	# IP is not given
			try:
				value = socket.gethostbyname(value)  			# Get the ip from the host name
			except socket.gaierror:  							# Exception raised if hostname not reachable
				self.fail(
					'There was an error resolving the host!',
					param,
					ctx
				)

		return value


class PortRange(click.ParamType):

	def convert(self, value, param, ctx):
		"""Converts various port lists, ranges into list"""

		values = []
		if ',' in value: 										# custom list given
			values = value.split(',')
		else:
			values = [value]

		final_port_range = set()
		for ports in values:									# Can be single port and range
			if '-' in ports:
				try:
					final_port_range |= set(					# Extend the current range
						range(
							*list(
								map(int, ports.split('-'))
							)
						)
					)
				except Exception as err:
					self.fail(
						'Invalid port range specified',
						param,
						ctx
					)
			else:												# Single port
				final_port_range.add(int(ports))

		return iter(tuple(final_port_range))


# Scanner class
class PortScanner:
	class ScanResult:
		OPEN = 'open'
		FILTERED = 'filtered'
		CLOSED = 'closed'

		def __init__(self, port, message, status):
			self.port = port
			self.message = message
			self.status = status

		def __str__(self):
			return f'{self.port}\t{self.status}\t{self.message}'

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
				try:
					s.connect((self.ip, next_port))  				# connect to host on specified port
					self.add_scan_result(
						PortScanner.ScanResult(
							next_port,
							'Port is up!',
							PortScanner.ScanResult.OPEN
						)
					)
				except Exception as err:
					messages = {
						ConnectionRefusedError: 'Port seems closed',
						TimeoutError: 'Connection timed out',
						OSError: f'OS threw an error while scanning this port, threw this err\n\t"{err}"',
					}

					s.close()
					self.add_scan_result(
						PortScanner.ScanResult(
							next_port,
							messages.get(err) or 'Port seems closed',
							PortScanner.ScanResult.CLOSED
						)
					)
			except StopIteration as err:							# All ports scanned
				break

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
@click.argument('ip', type=IpOrHostName())
@click.option('-t', '--tcp', type=bool, default=True)
@click.option('-u', '--udp', type=bool, default=False)
@click.option('-T', '--thread-count', type=int, default=1)
@click.option('-s', '--timeout', type=float, default=0.5)
@click.argument('port_range', type=PortRange())
def scan(ip, tcp, udp, port_range, thread_count, timeout):
	if tcp and udp:
		click.echo('Please specify a single protocol!')
		exit(0)

	protocol = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
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
			print(next_result)
		except StopIteration:
			break


if __name__ == '__main__':
	scan()
