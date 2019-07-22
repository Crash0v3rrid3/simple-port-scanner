import click
import re
import socket


class IpOrHostName(click.ParamType):
    name = 'IP or Hostname'

    def convert(self, value, param, ctx):
        """Converts hostnames/domain names into IP's"""
        # Is IP given?
        match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value)

        if match is None:	                                    # IP is not given
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
    name = 'port range,list'

    def convert(self, value, param, ctx):
        """Converts various port lists, ranges into list"""

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
