# Simple TCP and UDP Port Scanner

#### Usage:
```
# python scanner.py 127.0.0.1 --help
Usage: scanner.py [OPTIONS] IP

Options:
  -t, --tcp / -u, --udp           Toggle TCP Scan or UDP Scan
  -T, --thread-count INTEGER      Number of threads
  -s, --timeout FLOAT             Amount of time to sleep between successive
                                  port scans
  -o, --open                      Print only open ports
  -p, --port-range PORT RANGE,LIST
                                  Port range('-' separated)/list(','
                                  separated), 1,2,3 or 1-10 or 1-30,65,87
                                  [required]
  -sV, --service-scan BOOLEAN     List services running on ports
  --help                          Show this message and exit.
```