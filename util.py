def is_port_valid(port):
    if type(port) != int:
        raise TypeError('Invalid port specified')
    if port <= 0 or port > 65535:
        raise ValueError('Invalid port specified')
