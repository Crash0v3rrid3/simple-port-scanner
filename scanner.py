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
            return '%8s%10s\t%s' % (self.port, self.status, self.message)

    def __init__(self, ip, port_range, protocol, service_scan=False, thread_count=1, timeout_sleep=0.5):
        self.scan_results = []
        self.threads = []

        self.thread_count = thread_count
        self.port_range = port_range
        self.timeout_sleep = timeout_sleep
        self.ip = ip
        self.protocol = protocol
        self.service_scan = service_scan

        self.scan_results_lock = threading.Lock()
        self.port_range_lock = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            while not self.scan_results:
                if self.is_done():
                    raise StopIteration
                time.sleep(self.timeout_sleep)
            with self.scan_results_lock:
                if self.scan_results:
                    return self.scan_results.pop(0)

    def is_port_open(self, port):
        s = socket.socket(socket.AF_INET, self.protocol)                # Create new socket

        s.connect((self.ip, port))                                      # connect to host on specified port
        if self.protocol == socket.SOCK_STREAM:                         # TCP is simple
            s.close()
            return True
        elif self.protocol == socket.SOCK_DGRAM:                        # UDP needs some extra work
            s.send(b'')
            data = s.recv(256)

    def _start_scanner(self):
        while True:
            time.sleep(self.timeout_sleep)
            try:
                next_port = self.next_port()                            # Next port to scan

                if self.is_port_open(next_port):
                    self.add_scan_result(
                        PortScanner.ScanResult(
                            next_port,
                            'Port is up',
                            PortScanner.ScanResult.OPEN
                        )
                    )
            except StopIteration:                                    # All ports scanned
                break
            except Exception as err:
                messages = {
                    ConnectionRefusedError: 'Port seems closed',
                    TimeoutError: 'Connection timed out',
                    OSError: f'OS threw an error while scanning this port, error message:\n\t"{err}"',
                }
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
        for _ in range(self.thread_count):                            # Start n threads for faster processing
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
@click.option('-t/-u', '--tcp/--udp', help='Toggle TCP Scan or UDP Scan', default=True)
@click.option('-T', '--thread-count', help='Number of threads', type=int, default=1)
@click.option('-s', '--timeout', help='Amount of time to sleep between successive port scans', type=float, default=0.5)
@click.option('-o', '--open', 'open_only', help='Print only open ports', type=bool, default=False, is_flag=True)
@click.option('-p', '--port-range', help='Port range(\'-\' separated)/list(\',\' separated)', type=PortRange(), required=True)
@click.option('-sV', '--service-scan', help='List services running on ports', type=bool, default=False)
def scan(ip, tcp, port_range, thread_count, timeout, open_only, service_scan):
    protocol = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    scanner = PortScanner(
        ip,
        port_range,
        protocol,
        thread_count=thread_count,
        timeout_sleep=timeout,
        service_scan=service_scan
    )
    start_time = time.time()
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

    end_time = time.time()

    print('\nScan completed in %.3fs' % (end_time - start_time))


if __name__ == '__main__':
    scan()
