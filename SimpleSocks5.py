import asyncio
import socket
import struct

__version__ = '1.0.0'
__author__ = 'spcharc'


listen = '0.0.0.0', 8000
# define which address and port to listen on

lp = asyncio.get_event_loop()

def protocol_factory(writer):

    class StreamProtocol(asyncio.Protocol):

        def connection_made(self, transport):
            conn_socket = transport.get_extra_info('socket')
            conn_ip, conn_port = conn_socket.getsockname()[0:2]
            # in case of AF_INET6, a tuple of length 4 would be returned

            if conn_socket.family == socket.AF_INET:
                conn_family = 1
            elif conn_socket.family == socket.AF_INET6:
                conn_family = 4
            else:
                print('internal error, should not reach here')
                return

            writer.write(struct.pack('!BBBB', 5, 0, 0, conn_family))
            writer.write(socket.inet_pton(conn_socket.family, conn_ip))
            writer.write(struct.pack('!H', conn_port))

        def connection_lost(self, exception):
            if exception is not None:
                print(exception)
            writer.close()

        def data_received(self, data):
            writer.write(data)

    return StreamProtocol


async def handler(reader, writer):

    async def read_struct(data_format):

        length = struct.calcsize(data_format)
        content = await reader.readexactly(length)
        return struct.unpack(data_format, content)

    # https://tools.ietf.org/html/rfc1928

    ver, nmethods = await read_struct('!BB')

    if ver != 5:  # ver should be 5
        writer.close()
        await writer.wait_closed()
        return

    if nmethods > 0:
        methods = await reader.readexactly(nmethods)
        # print('Client methods: ', [i for i in methods])

    writer.write(struct.pack('!BB', 5, 0)) # no auth

    # -------- negotiation ends
    ver, cmd, rsv, atyp = await read_struct('!BBBB')
    if ver != 5:  # ver should be 5
        print('ERROR: Unsupported socks version', ver)
        writer.close()
        await writer.wait_closed()
        return
    if cmd != 1:  # 1=connect, 2=bind, 3=udp associate
        print('ERROR: Unsupported client command', cmd)
        writer.close()
        await writer.wait_closed()
        return
    if rsv != 0:  # rsv should be 0
        return

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
        print('Error: invalid atyp in request')
        writer.close()
        await writer.wait_closed()
        return

    port, = await read_struct('!H')

    print('Connection to', hostname, ':', port)

    transport, protocol = await lp.create_connection(
        protocol_factory(writer),
        hostname,
        port
    )

    while True:
        data = await reader.read(8192)
        # read(8192) reads at most 8192 bytes, but it can return before that.
        # So the program doesn't wait until 8192 bytes are received. It always
        #     tries to send whatever it has.
        if len(data) == 0:
            break
        transport.write(data)

    if not transport.is_closing():
        transport.close()

if __name__ == '__main__':
    lp.run_until_complete(asyncio.start_server(handler, *listen))
    print('Started')
    lp.run_forever()
