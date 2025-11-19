#!/usr/bin/env python3

# requires Python 3.8+

import asyncio
import socket
import struct
import ipaddress

__version__ = '1.1.0'
__author__ = 'spcharc'


class IncorrectFormat(Exception):
    pass

class SocksVersionIncorrect(Exception):
    pass

class AuthMethodNotSupported(Exception):
    pass

class UnsupportedCommand(Exception):
    pass

class AddressTypeNotSupported(Exception):
    pass

class HostNotFound(Exception):
    pass

class ConnectionRefused(Exception):
    pass

class ConnectionFailed(Exception):
    pass

class InternalError(Exception):
    pass

class IncomingNotWhitelisted(Exception):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip

class OutgoingBlacklisted(Exception):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip


# Default outgoing blacklist: all RFC1918 private IP ranges
DEFAULT_OUTGOING_BLACKLIST = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '127.0.0.0/8',  # loopback
    '169.254.0.0/16',  # link-local
    'fc00::/7',  # IPv6 private
    'fe80::/10',  # IPv6 link-local
    '::1/128',  # IPv6 loopback
]

def ip_in_range(ip_str, ip_ranges):
    """
    Check if an IP address matches any range in the list.

    Args:
        ip_str: IP address as string (e.g., "192.168.1.1")
        ip_ranges: List of ipaddress.ip_network objects or CIDR strings

    Returns:
        True if IP matches any range, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        for ip_range in ip_ranges:
            if ip in ip_range:
                # print(f'DEBUG IP {ip_str} matched range {ip_range}')
                return True
        return False
    except ValueError:
        return False


def check_incoming_whitelist(incoming_ip, incoming_whitelist):
    """Check if incoming IP is whitelisted. Returns True if allowed, False if blocked."""
    if not incoming_whitelist:  # whitelist disabled
        return True
    return ip_in_range(incoming_ip, incoming_whitelist)


def check_outgoing_blacklist(outgoing_ip, outgoing_blacklist):
    """Check if outgoing IP is blacklisted. Returns True if blocked, False if allowed."""
    return ip_in_range(outgoing_ip, outgoing_blacklist)


async def pipe_data(reader, writer):
    # pipes data from reader into writer

    while len(data := await reader.read(8192)):  # 8kb
        writer.write(data)
        await writer.drain()

    writer.close()
    await writer.wait_closed()


async def handler_raises(reader, writer, incoming_whitelist, outgoing_blacklist):

    async def read_struct(data_format):

        length = struct.calcsize(data_format)
        content = await reader.readexactly(length)
        return struct.unpack(data_format, content)

    incoming_socket = writer.get_extra_info('socket')
    incoming_ip, incoming_port = incoming_socket.getpeername()[0:2]

    # Check incoming whitelist
    if not check_incoming_whitelist(incoming_ip, incoming_whitelist):
        raise IncomingNotWhitelisted(incoming_ip)

    # https://tools.ietf.org/html/rfc1928

    ver, nmethods = await read_struct('!BB')

    if ver != 5:  # ver should be 5
        raise IncorrectFormat

    if nmethods == 0:
        raise AuthMethodNotSupported
    methods = await reader.readexactly(nmethods)
    if 0 not in methods:          # 'int' in 'bytes'
        raise AuthMethodNotSupported

    writer.write(struct.pack('!BB', 5, 0))   # NO AUTHENTICATION REQUIRED
    await writer.drain()

    # -------- negotiation ends --------
    ver, cmd, rsv, atyp = await read_struct('!BBBB')
    if ver != 5:  # ver should be 5
        raise SocksVersionIncorrect

    if cmd != 1:  # 1=connect, 2=bind, 3=udp associate
        raise UnsupportedCommand

    if rsv != 0:  # rsv should be 0
        raise IncorrectFormat

    if atyp == 1:   # ipv4
        host = await reader.readexactly(4)
        hostname = socket.inet_ntop(socket.AF_INET, host)
        if check_outgoing_blacklist(hostname, outgoing_blacklist):
            raise OutgoingBlacklisted(hostname)
        print(f'Connection: {incoming_ip} : {incoming_port} -> {hostname} : {port}')
    elif atyp == 3: # domain
        length, = await read_struct('!B')
        hostname = (await reader.readexactly(length)).decode('ascii')
    elif atyp == 4: # ipv6
        host = await reader.readexactly(16)
        hostname = socket.inet_ntop(socket.AF_INET6, host)
        if check_outgoing_blacklist(hostname, outgoing_blacklist):
            raise OutgoingBlacklisted(hostname)
        print(f'Connection: {incoming_ip} : {incoming_port} -> {hostname} : {port}')
    else:
        raise AddressTypeNotSupported

    port, = await read_struct('!H')

    try:
        reader2, writer2 = await asyncio.open_connection(hostname, port)
    except socket.gaierror:
        raise HostNotFound
    except ConnectionRefusedError:
        raise ConnectionRefused
    except Exception:
        raise ConnectionFailed

    conn_socket = writer2.get_extra_info('socket')
    conn_ip, conn_port = conn_socket.getsockname()[0:2]
    # in case of AF_INET6, a tuple of length 4 would be returned

    # Check outgoing blacklist against peer (target) IP
    if atyp == 3: # domain
        peer_ip = conn_socket.getpeername()[0]
        if check_outgoing_blacklist(peer_ip, outgoing_blacklist):
            writer2.close()
            await writer2.wait_closed()
            raise OutgoingBlacklisted(peer_ip)
        print(f'Connection: {incoming_ip} : {incoming_port} -> {hostname} | {peer_ip} : {port}')

    if conn_socket.family == socket.AF_INET:
        conn_family = 1
    elif conn_socket.family == socket.AF_INET6:
        conn_family = 4
    else:
        raise InternalError

    writer.write(struct.pack('!BBBB', 5, 0, 0, conn_family))
    writer.write(socket.inet_pton(conn_socket.family, conn_ip))
    writer.write(struct.pack('!H', conn_port))
    await writer.drain()

    await asyncio.gather(pipe_data(reader2, writer),
                         pipe_data(reader, writer2),
                         return_exceptions=True)



async def handler(reader, writer, incoming_whitelist, outgoing_blacklist):
    # wrap handler_raises, this function handles exceptions

    try:
        await handler_raises(reader, writer, incoming_whitelist, outgoing_blacklist)

    # X'00' succeeded
    # X'01' general SOCKS server failure
    # X'02' connection not allowed by ruleset
    # X'03' Network unreachable
    # X'04' Host unreachable
    # X'05' Connection refused
    # X'06' TTL expired
    # X'07' Command not supported
    # X'08' Address type not supported
    # X'09' to X'FF' unassigned

    except IncorrectFormat:
        writer.close()
        await writer.wait_closed()
        print('ERROR: Incorrect data format. Using socks5?')

    except SocksVersionIncorrect:
        writer.close()
        await writer.wait_closed()
        print('ERROR: Socks version should be 5.')

    except asyncio.IncompleteReadError:
        writer.close()
        await writer.wait_closed()
        print('INFO: Peer closed socket unexpectedly.')

    except IncomingNotWhitelisted as e:
        writer.close()
        await writer.wait_closed()
        print(f'ERROR: Incoming IP {e.ip} not in whitelist.')

    except AuthMethodNotSupported:
        writer.write(struct.pack('!BB', 5, 255))  # NO ACCEPTABLE METHODS
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print('ERROR: This program only supports socks5 without encryption.')

    except UnsupportedCommand:
        writer.write(struct.pack('!BBBBIH', 5, 7, 0, 1, 0, 0))
        # Command not supported
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print('ERROR: This program only supports socks5 CONNECT command.')

    except AddressTypeNotSupported:
        writer.write(struct.pack('!BBBBIH', 5, 8, 0, 1, 0, 0))
        # Address type not supported
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print('ERROR: This program does not support this address type.')

    except HostNotFound:
        writer.write(struct.pack('!BBBBIH', 5, 4, 0, 1, 0, 0))
        # Host unreachable
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    except ConnectionRefused:
        writer.write(struct.pack('!BBBBIH', 5, 5, 0, 1, 0, 0))
        # Connection refused
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    except ConnectionFailed:
        writer.write(struct.pack('!BBBBIH', 5, 3, 0, 1, 0, 0))
        # Network unreachable
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    except OutgoingBlacklisted as e:
        writer.write(struct.pack('!BBBBIH', 5, 2, 0, 1, 0, 0))
        # Connection not allowed by ruleset
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print(f'ERROR: Outgoing IP {e.ip} in blacklist.')

    except InternalError:
        writer.write(struct.pack('!BBBBIH', 5, 1, 0, 1, 0, 0))
        # general SOCKS server failure (should not reach here)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print('ERROR: Socket family incorrect ... this should not happen.')


async def main(addr, port, incoming_whitelist=None, outgoing_blacklist=None):
    if incoming_whitelist is None:
        incoming_whitelist = []
    else:
        incoming_whitelist = [ipaddress.ip_network(net) for net in incoming_whitelist]
    if outgoing_blacklist is None:
        outgoing_blacklist = [ipaddress.ip_network(net) for net in DEFAULT_OUTGOING_BLACKLIST]
    else:
        outgoing_blacklist = [ipaddress.ip_network(net) for net in outgoing_blacklist]

    async def handler_wrapper(reader, writer):
        await handler(reader, writer, incoming_whitelist, outgoing_blacklist)

    await asyncio.start_server(handler_wrapper, addr, port)


if __name__ == '__main__':
    addr = '0.0.0.0'
    port = 1080
    # define which address and port to listen on

    loop = asyncio.new_event_loop()
    loop.run_until_complete(main(addr, port))
    print(f'Listening on {addr} : {port}')
    loop.run_forever()
