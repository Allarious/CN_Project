"""

    This is the format of packets in our network:
    


                                                **  NEW Packet Format  **
     __________________________________________________________________________________________________________________
    |           Version(2 Bytes)         |         Type(2 Bytes)         |           Length(Long int/4 Bytes)          |
    |------------------------------------------------------------------------------------------------------------------|
    |                                            Source Server IP(8 Bytes)                                             |
    |------------------------------------------------------------------------------------------------------------------|
    |                                           Source Server Port(4 Bytes)                                            |
    |------------------------------------------------------------------------------------------------------------------|
    |                                                    ..........                                                    |
    |                                                       BODY                                                       |
    |                                                    ..........                                                    |
    |__________________________________________________________________________________________________________________|

    Version:
        For now version is 1
    
    Type:
        1: Register
        2: Advertise
        3: Join
        4: Message
        5: Reunion
                e.g: type = '2' => Advertise packet.
    Length:
        This field shows the character numbers for Body of the packet.

    Server IP/Port:
        We need this field for response packet in non-blocking mode.



    ***** For example: ******

    version = 1                 b'\x00\x01'
    type = 4                    b'\x00\x04'
    length = 12                 b'\x00\x00\x00\x0c'
    ip = '192.168.001.001'      b'\x00\xc0\x00\xa8\x00\x01\x00\x01'
    port = '65000'              b'\x00\x00\\xfd\xe8'
    Body = 'Hello World!'       b'Hello World!'

    Bytes = b'\x00\x01\x00\x04\x00\x00\x00\x0c\x00\xc0\x00\xa8\x00\x01\x00\x01\x00\x00\xfd\xe8Hello World!'




    Packet descriptions:
    
        Register:
            Request:
        
                                 ** Body Format **
                 ________________________________________________
                |                  REQ (3 Chars)                 |
                |------------------------------------------------|
                |                  IP (15 Chars)                 |
                |------------------------------------------------|
                |                 Port (5 Chars)                 |
                |________________________________________________|
                
                For sending IP/Port of the current node to the root to ask if it can register to network or not.

            Response:
        
                                 ** Body Format **
                 _________________________________________________
                |                  RES (3 Chars)                  |
                |-------------------------------------------------|
                |                  ACK (3 Chars)                  |
                |_________________________________________________|
                
                For now only should just send an 'ACK' from the root to inform a node that it
                has been registered in the root if the 'Register Request' was successful.
                
        Advertise:
            Request:
            
                                ** Body Format **
                 ________________________________________________
                |                  REQ (3 Chars)                 |
                |________________________________________________|
                
                Nodes for finding the IP/Port of their neighbour peer must send this packet to the root.

            Response:

                                ** Packet Format **
                 ________________________________________________
                |                RES(3 Chars)                    |
                |------------------------------------------------|
                |              Server IP (15 Chars)              |
                |------------------------------------------------|
                |             Server Port (5 Chars)              |
                |________________________________________________|
                
                Root will response Advertise Request packet with sending IP/Port of the requester peer in this packet.
                
        Join:

                                ** Body Format **
                 ________________________________________________
                |                 JOIN (4 Chars)                 |
                |________________________________________________|
            
            New node after getting Advertise Response from root must send this packet to the specified peer
            to tell him that they should connect together; When receiving this packet we should update our
            Client Dictionary in the Stream object.


            
        Message:
                                ** Body Format **
                 ________________________________________________
                |             Message (#Length Chars)            |
                |________________________________________________|

            The message that want to broadcast to hole network. Right now this type only includes a plain text.
        
        Reunion:
            Hello:
        
                                ** Body Format **
                 ________________________________________________
                |                  REQ (3 Chars)                 |
                |------------------------------------------------|
                |           Number of Entries (2 Chars)          |
                |------------------------------------------------|
                |                 IP0 (15 Chars)                 |
                |------------------------------------------------|
                |                Port0 (5 Chars)                 |
                |------------------------------------------------|
                |                 IP1 (15 Chars)                 |
                |------------------------------------------------|
                |                Port1 (5 Chars)                 |
                |------------------------------------------------|
                |                     ...                        |
                |------------------------------------------------|
                |                 IPN (15 Chars)                 |
                |------------------------------------------------|
                |                PortN (5 Chars)                 |
                |________________________________________________|
                
                In every interval (for now 20 seconds) peers must send this message to the root.
                Every other peer that received this packet should append their (IP, port) to
                the packet and update Length.

            Hello Back:
        
                                    ** Body Format **
                 ________________________________________________
                |                  REQ (3 Chars)                 |
                |------------------------------------------------|
                |           Number of Entries (2 Chars)          |
                |------------------------------------------------|
                |                 IPN (15 Chars)                 |
                |------------------------------------------------|
                |                PortN (5 Chars)                 |
                |------------------------------------------------|
                |                     ...                        |
                |------------------------------------------------|
                |                 IP1 (15 Chars)                 |
                |------------------------------------------------|
                |                Port1 (5 Chars)                 |
                |------------------------------------------------|
                |                 IP0 (15 Chars)                 |
                |------------------------------------------------|
                |                Port0 (5 Chars)                 |
                |________________________________________________|

                Root in an answer to the Reunion Hello message will send this packet to the target node.
                In this packet, all the nodes (IP, port) exist in order by path traversal to target.

    
"""
from struct import *
import struct

class Packet:
    def __init__(self, buffer):
        """
        The decoded buffer should convert to a new packet.

        :param buf: Input buffer was just decoded.
        :type buf: bytearray
        """

        self.buffer = buffer

        buf = struct.unpack("<%dB" % (len(buffer)) ,buffer)

        self.version = buf[:2]
        self.type = buf[2:4]
        self.length = buf[4:8]
        self.server_ip = buf[8:16]
        self.server_port = buf[16:20]
        self.header = buf[:20]
        self.body = buf[20:]

    def get_header(self):
        """

        :return: Packet header
        :rtype: str
        """
        return self.header

    def get_version(self):
        """

        :return: Packet Version
        :rtype: int
        """
        return self.version

    def get_type(self):
        """

        :return: Packet type
        :rtype: int
        """
        return self.type

    def get_length(self):
        """

        :return: Packet length
        :rtype: int
        """
        return self.length

    def get_body(self):
        """

        :return: Packet body
        :rtype: str
        """
        return self.body

    def get_buf(self):
        """
        In this function, we will make our final buffer that represents the Packet with the Struct class methods.

        :return The parsed packet to the network format.
        :rtype: bytearray
        """
        return self.buffer

    def get_source_server_ip(self):
        """

        :return: Server IP address for the sender of the packet.
        :rtype: str
        """
        return self.server_ip

    def get_source_server_port(self):
        """

        :return: Server Port address for the sender of the packet.
        :rtype: str
        """
        return self.server_port

    def get_source_server_address(self):
        """

        :return: Server address; The format is like ('192.168.001.001', '05335').
        :rtype: tuple
        """
        return (self.get_source_server_ip(), self.server_port)


class PacketFactory:
    """
    This class is only for making Packet objects.
    """

    @staticmethod
    def parse_buffer(buffer) -> Packet:
        """
        In this function we will make a new Packet from input buffer with struct class methods.

        :param buffer: The buffer that should be parse to a validate packet format

        :return new packet
        :rtype: Packet

        """

        return Packet(buffer)

    @staticmethod
    def new_reunion_packet(type, source_address, nodes_array) -> Packet:
        """
        :param type: Reunion Hello (REQ) or Reunion Hello Back (RES)
        :param source_address: IP/Port address of the packet sender.
        :param nodes_array: [(ip0, port0), (ip1, port1), ...] It is the path to the 'destination'.

        :type type: str
        :type source_address: tuple
        :type nodes_array: list

        :return New reunion packet.
        :rtype Packet
        """
        packet_fact = PacketFactory()

        narray = b''

        for x in nodes_array:
            narray += bytes(str(x[0]), encoding='utf-8')
            narray += bytes(str(x[1]), encoding='utf-8')


        buffer = packet_fact.set_header(1, 5, len(nodes_array)*20 + 5, source_address[0], source_address[1]) + bytes(str(type), encoding='utf-8') + bytes(str(len(nodes_array)), encoding='utf-8') + narray
        return Packet(buffer)

    @staticmethod
    def new_advertise_packet(type, source_server_address, neighbour=None) -> Packet:
        """
        :param type: Type of Advertise packet
        :param source_server_address Server address of the packet sender.
        :param neighbour: The neighbour for advertise response packet; The format is like ('192.168.001.001', '05335').

        :type type: str
        :type source_server_address: tuple
        :type neighbour: tuple

        :return New advertise packet.
        :rtype Packet

        """
        packet_fact = PacketFactory()
        len = 3
        neighbour_ip = b''

        if(neighbour):
            neighbour_ip = bytes(str(neighbour[0]), encoding='utf-8') + bytes(str(neighbour[1]), encoding='utf-8')
            len = 23

        buffer = packet_fact.set_header(1, 2, len, source_server_address[0], source_server_address[1]) + bytes(str(type), encoding='utf-8') + neighbour_ip

        return Packet(buffer)

    @staticmethod
    def new_join_packet(source_server_address) -> Packet:
        """
        :param source_server_address: Server address of the packet sender.

        :type source_server_address: tuple

        :return New join packet.
        :rtype Packet

        """
        packet_fact = PacketFactory()
        buffer = packet_fact.set_header(1, 3, 4, source_server_address[0], source_server_address[1]) + b'JOIN'
        return Packet(buffer)

    @staticmethod
    def new_register_packet(type, source_server_address, address=(None, None)) -> Packet:
        """
        :param type: Type of Register packet
        :param source_server_address: Server address of the packet sender.
        :param address: If 'type' is 'request' we need an address; The format is like ('192.168.001.001', '05335').

        :type type: str
        :type source_server_address: tuple
        :type address: tuple

        :return New Register packet.
        :rtype Packet

        """
        packet_fact = PacketFactory()
        if(type == 'REQ'):
            len = 23
            ip_address = bytes(str(address[0]), encoding='utf-8')
            port_address = bytes(str(address[1]), encoding='utf-8')
            bdy = ip_address + port_address
        else:
            len = 6
            ip_address = b''
            port_address = b''
            bdy = b'ACK'

        buffer = packet_fact.set_header(1, 1, len, source_server_address[0], source_server_address[1]) + bytes(str(type), encoding='utf-8') + bdy
        return Packet(buffer)

    @staticmethod
    def new_message_packet(message, source_server_address) -> Packet:
        """
        Packet for sending a broadcast message to the whole network.

        :param message: Our message
        :param source_server_address: Server address of the packet sender.

        :type message: str
        :type source_server_address: tuple

        :return: New Message packet.
        :rtype: Packet
        """
        packet_fact = PacketFactory()
        buffer = packet_fact.set_header(1, 4, len(message), source_server_address[0], source_server_address[1]) + bytes(str(message), encoding='utf-8')
        return Packet(buffer)

    @staticmethod
    def set_header(version, type, length, ip, port) -> Packet:
        result = b''
        result += struct.pack("I", version)[1::-1]
        result += struct.pack("I", type)[1::-1]
        result += struct.pack("I", length)[::-1]
        for s in str(ip).split('.'):
            result += struct.pack("I", int(s))[1::-1]

        result += struct.pack("I", int(port))[::-1]
        return result



# print(struct.pack("I", 256)[1::-1])

# print(b'' + bytes('Hello', encoding='utf-8'))

# buf = [0, 1, 0, 3, 0, 0, 255, 10, 0, 20, 0 , 10, 0, 1, 0, 1, 5, 5, 5, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 0 ,3]
#
# print(buf)
#
# pac = struct.pack('<%dB' % len(buf), *buf)
#
# print(pac)
# packet_fact = PacketFactory()
# pack = packet_fact.parse_buffer(pac)
# nodes_array = [('192.168.1.1' , '65000'), ('192.168.1.1' , '65000'), ('192.168.1.1', '65000')]
# pack = packet_fact.new_reunion_packet('REQ', ('192.168.1.1','65000'), nodes_array)
# pack = packet_fact.new_advertise_packet('RES', ('192.168.1.1','65000'), ('192.168.1.1','65000'))
# pack = packet_fact.new_message_packet('Hello World!', ('192.168.1.1','65000'))
# pack = packet_fact.new_register_packet('REQ', ('192.168.1.1','65000'), ('192.168.1.1','65000'))
#
#
# new_pac = struct.unpack("<%dI" % (len(pac) // 4) ,pac)


# buf = "{0:b}".format(1).zfill(16) + "{0:b}".format(3).zfill(16) + "{0:b}".format(250).zfill(32) + \
#         "{0:b}".format(192).zfill(16) + "{0:b}".format(168).zfill(16) + "{0:b}".format(1).zfill(16) + \
#         "{0:b}".format(1).zfill(16) + "{0:b}".format(5335).zfill(32) + "{0:b}".format(100).zfill(1000)


# pack = Packet(buf)

# print("{}".format(buf))
# print("{}".format(Struct.pack(buf)))
#
# print("header: {}".format(pack.get_header()))
# print("version: {}".format(pack.get_version()))
# print("type: {}".format(pack.get_type()))
# print("length: {}".format(pack.get_length()))
# print("source ip: {}".format(pack.get_source_server_ip()))
# print("source port: {}".format(pack.get_source_server_port()))
# print("address: {}".format(pack.get_source_server_address()))
# print("body: {}".format(pack.get_body()))
# print("body: {}".format(pack.get_buf()))
#
# print(packet_fact.set_header(1, 4, 12, '192.168.001.001', 65000))