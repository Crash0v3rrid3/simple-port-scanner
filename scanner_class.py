import threading
import socket
import time
import util
from queue import Empty


class ScanResult:
    """Scan Result class"""

    # Result Possibilities
    OPEN = 'open'
    FILTERED = 'filtered'
    CLOSED = 'closed'

    def __init__(self, port, message, status):
        if type(port) != int:
            raise TypeError('Invalid port specified')
        if port <= 0 or port > 65535:
            raise ValueError('Invalid Port Specified')
        if status != ScanResult.OPEN and status != ScanResult.FILTERED and status != ScanResult.CLOSED:
            raise ValueError('Invalid port state')
        self.port = port
        self.message = message
        self.status = status

    def is_open(self):
        return self.status == ScanResult.OPEN

    def is_closed(self):
        return self.status == ScanResult.CLOSED

    def get_port(self):
        return self.port

    def get_status(self):
        return self.status

    def get_message(self):
        return self.message

    def __str__(self):
        return '%8s%10s\t%s' % (self.port, self.status, self.message)


class PortScanner:
    """Scanner class"""

    def __init__(
            self,
            ip,
            port_range,
            protocol,
            open_only=False,
            service_scan=False,
            thread_count=1,
            timeout_sleep=0.5,
            dynamic_load_sharing=False):
        if type(False) != type(open_only):
            raise TypeError
        if type(1) != type(thread_count):
            raise TypeError("Invalid thread count")
        if type(0.5) != type(timeout_sleep):
            raise TypeError("Invalid timeout value")

        self.scan_results = []
        self.threads = []

        self.thread_count = thread_count
        self.port_range = port_range
        self.timeout_sleep = timeout_sleep
        self.ip = ip
        self.protocol = protocol
        self.service_scan = service_scan
        self.open_only = open_only

        if dynamic_load_sharing:
            def next_port_func(self):
                return self.port_range.get(block=False)
        else:
            def next_port_func(self):
                return next(self.port_range)

        self.next_port = next_port_func                 #

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
        util.is_port_valid(port)                                        # Check port validity
        s = socket.socket(socket.AF_INET, self.protocol)                # Create new socket

        s.connect((self.ip, port))                                      # connect to host on specified port
        if self.protocol == socket.SOCK_STREAM:                         # TCP is simple
            s.close()
            return True
        elif self.protocol == socket.SOCK_DGRAM:                        # UDP needs some extra work
            # Port based request must be made
            pass

    def _start_scanner(self):
        while True:
            time.sleep(self.timeout_sleep)
            try:
                next_port = self.next_port(self)                            # Next port to scan

                if self.is_port_open(next_port):
                    self.add_scan_result(
                        ScanResult(
                            next_port,
                            'Port is up',
                            ScanResult.OPEN
                        )
                    )
            except StopIteration:                                       # All ports scanned when using an iter
                break
            except Empty:                                               # All ports scanned when using a queue
                break
            except TypeError as err:                                    # Invalid port
                pass
            except ValueError as err:                                   # Invalid port
                pass
            except Exception as err:
                messages = {
                    ConnectionRefusedError: 'Port seems closed',
                    TimeoutError: 'Connection timed out',
                    OSError: f'OS threw an error while scanning this port, error message:\n\t"{err}"',
                }
                if not self.open_only:
                    self.add_scan_result(
                        ScanResult(
                            next_port,
                            messages.get(type(err)) or err,
                            ScanResult.CLOSED
                        )
                    )

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
