import click
import time
from type_utilities import IpOrHostName, PortRange
from scanner_class import PortScanner
import socket
import multiprocessing


def port_scan(ip, protocol, port_range, thread_count, timeout, open_only, service_scan):
    scanner = PortScanner(
        ip,
        port_range,
        protocol,
        open_only=open_only,
        thread_count=thread_count,
        timeout_sleep=timeout,
        service_scan=service_scan
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
def scan(ip, tcp, process_count, port_range, thread_count, timeout, open_only, service_scan):
    protocol = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    processes = []
    total_number_of_ports = len(port_range)
    split_count = total_number_of_ports // process_count

    for _ in range(process_count):
        process = multiprocessing.Process(
            target=port_scan,
            args=(ip, protocol, iter(port_range[: split_count]), thread_count, timeout, open_only, service_scan)
        )
        if port_range[: split_count]:
            process.start()
            port_range = port_range[split_count: ]
            processes.append(process)
        else:
            break

    start_time = time.time()
    for process in processes:
        process.join()
    end_time = time.time()

    print('\nScan completed in %.3fs' % (end_time - start_time))


if __name__ == '__main__':
    scan()
