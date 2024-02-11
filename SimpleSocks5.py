#!/usr/bin/env python3

# requires Python 3.8+

import asyncio
import socket
import struct

__version__ = '1.0.4'
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

    print('Connect to', hostname, ':', port)

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
        # Network unreachable
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    except ConnectionFailed:
        writer.write(struct.pack('!BBBBIH', 5, 3, 0, 1, 0, 0))
        # Network unreachable
        await writer.drain()
        writer.close()
        await writer.wait_closed()

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
    print('Listening on', addr, ':', port)
    loop.run_forever()
