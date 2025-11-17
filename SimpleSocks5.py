#!/usr/bin/env python3

# requires Python 3.8+

import asyncio
import socket
import struct
import ipaddress

__version__ = '1.0.5'
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
    pass

class OutgoingBlacklisted(Exception):
    pass


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

# Configuration: can be modified before running main()
incoming_white_list = []  # empty means disabled
outgoing_black_list = [ipaddress.ip_network(net) for net in DEFAULT_OUTGOING_BLACKLIST]


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
            if isinstance(ip_range, str):
                ip_range = ipaddress.ip_network(ip_range, strict=False)
            if ip in ip_range:
                print(f'DEBUG IP {ip_str} matched range {ip_range}')
                return True
        return False
    except ValueError:
        return False


def check_incoming_whitelist(incoming_ip):
    """Check if incoming IP is whitelisted. Returns True if allowed, False if blocked."""
    if not incoming_white_list:  # whitelist disabled
        return True
    return ip_in_range(incoming_ip, incoming_white_list)


def check_outgoing_blacklist(outgoing_ip):
    """Check if outgoing IP is blacklisted. Returns True if blocked, False if allowed."""
    return ip_in_range(outgoing_ip, outgoing_black_list)


async def pipe_data(reader, writer):
    # pipes data from reader into writer

    while len(data := await reader.read(8192)):  # 8kb
        writer.write(data)
        await writer.drain()

    writer.close()
    await writer.wait_closed()


async def handler_raises(reader, writer):

    async def read_struct(data_format):

        length = struct.calcsize(data_format)
        content = await reader.readexactly(length)
        return struct.unpack(data_format, content)

    incoming_socket = writer.get_extra_info('socket')
    incoming_ip, incoming_port = incoming_socket.getpeername()[0:2]

    # Check incoming whitelist
    if not check_incoming_whitelist(incoming_ip):
        raise IncomingNotWhitelisted

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
    elif atyp == 3: # domain
        length, = await read_struct('!B')
        hostname = (await reader.readexactly(length)).decode('ascii')
    elif atyp == 4: # ipv6
        host = await reader.readexactly(16)
        hostname = socket.inet_ntop(socket.AF_INET6, host)
    else:
        raise AddressTypeNotSupported

    port, = await read_struct('!H')

    print(f'Connection: {incoming_ip} : {incoming_port} -> {hostname} : {port}')

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

    # Check outgoing blacklist
    if check_outgoing_blacklist(conn_ip):
        writer2.close()
        await writer2.wait_closed()
        raise OutgoingBlacklisted

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



async def handler(reader, writer):
    # wrap handler_raises, this function handles exceptions

    try:
        await handler_raises(reader, writer)

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

    except IncomingNotWhitelisted:
        writer.close()
        await writer.wait_closed()
        print('ERROR: Incoming IP not in whitelist.')

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

    except OutgoingBlacklisted:
        writer.write(struct.pack('!BBBBIH', 5, 2, 0, 1, 0, 0))
        # Connection not allowed by ruleset
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print('ERROR: Outgoing IP in blacklist.')

    except InternalError:
        writer.write(struct.pack('!BBBBIH', 5, 1, 0, 1, 0, 0))
        # general SOCKS server failure (should not reach here)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print('ERROR: Socket family incorrect ... this should not happen.')


async def main(addr, port):
    await asyncio.start_server(handler, addr, port)


if __name__ == '__main__':
    addr = '0.0.0.0'
    port = 1080
    # define which address and port to listen on

    loop = asyncio.new_event_loop()
    loop.run_until_complete(main(addr, port))
    print(f'Listening on {addr} : {port}')
    loop.run_forever()
