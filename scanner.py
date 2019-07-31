import click
import time
from type_utilities import IpOrHostName, PortRange
from scanner_class import PortScanner
import socket
import multiprocessing


def port_scan(args):
    ip, protocol, port_range, thread_count, timeout, open_only, service_scan, dynamic_load_sharing = args
    scanner = PortScanner(
        ip,
        port_range,
        protocol,
        open_only=open_only,
        thread_count=thread_count,
        timeout_sleep=timeout,
        service_scan=service_scan,
        dynamic_load_sharing=dynamic_load_sharing
    )
    scanner.start_scanner()
    result_itr = iter(scanner)
    while True:
        try:
            next_result = next(result_itr)
            print(next_result)
        except StopIteration:
            break


@click.command()
@click.argument('ip', type=IpOrHostName(), required=True)
@click.option('-t/-u', '--tcp/--udp', help='Toggle TCP Scan or UDP Scan', default=True)
@click.option('-P', '--process-count', help='Number of processes to spawn', default=1)
@click.option('-T', '--thread-count', help='Number of threads', type=int, default=1)
@click.option('-s', '--timeout', help='Amount of time to sleep between successive port scans', type=float, default=0.5)
@click.option('-o', '--open', 'open_only', help='Print only open ports', default=False, is_flag=True)
@click.option('-p', '--port-range', help='Port range(\'-\' separated)/list(\',\' separated), 1,2,3 or 1-10 or 1-30,65,87', type=PortRange(), required=True)
@click.option('-sV', '--service-scan', help='List services running on ports', type=bool, default=False)
@click.option('-d', '--dynamic-load-sharing', help='Uses a multiprocessing Queue to share ports among processes', default=False, is_flag=True)
def scan(ip, tcp, process_count, port_range, thread_count, timeout, open_only, service_scan, dynamic_load_sharing):
    protocol = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM                     # Decide protocol

    if dynamic_load_sharing:
        manager = multiprocessing.Manager()
        _port_queue = manager.Queue()                                            # To share ports

        for port in port_range:                                                         # Add ports to queue
            _port_queue.put(port)

        port_queue = [_port_queue] * process_count
    else:
        split_count = len(port_range) // process_count
        port_queue = [iter(port_range[index: split_count]) for index in range(0, len(port_range), split_count)]

    process_pool = multiprocessing.Pool(process_count)

    start_time = time.time()

    process_pool.map(
        port_scan,
        [
            [ip, protocol, x, thread_count, timeout, open_only, service_scan, dynamic_load_sharing]
            for x in port_queue
        ]
    )
    end_time = time.time()

    print('\nScan completed in %.3fs' % (end_time - start_time))


if __name__ == '__main__':
    scan()
