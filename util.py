def is_port_valid(port):
    if type(port) != int:
        raise TypeError('Invalid port specified')
    if port <= 0 or port > 65535:
        raise ValueError('Invalid port specified')


def checksum(msg):
    """Function for calculating checksum"""

    s = 0

    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s
