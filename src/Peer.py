from src.Stream import Stream
from src.Packet import Packet, PacketFactory
from src.UserInterface import UserInterface
from src.tools.SemiNode import SemiNode
from src.tools.NetworkGraph import NetworkGraph, GraphNode
import time
import threading
from datetime import datetime
from datetime import timedelta
import sys

"""
    Peer is our main object in this project.
    In this network Peers will connect together to make a tree graph.
    This network is not completely decentralised but will show you some real-world challenges in Peer to Peer networks.

"""


class Peer:
    def __init__(self, server_ip, server_port, is_root=False, root_address=None):
        """
        The Peer object constructor.

        Code design suggestions:
            1. Initialise a Stream object for our Peer.
            2. Initialise a PacketFactory object.
            3. Initialise our UserInterface for interaction with user commandline.
            4. Initialise a Thread for handling reunion daemon.

        Warnings:
            1. For root Peer, we need a NetworkGraph object.
            2. In root Peer, start reunion daemon as soon as possible.
            3. In client Peer, we need to connect to the root of the network, Don't forget to set this connection
               as a register_connection.


        :param server_ip: Server IP address for this Peer that should be pass to Stream.
        :param server_port: Server Port address for this Peer that should be pass to Stream.
        :param is_root: Specify that is this Peer root or not.
        :param root_address: Root IP/Port address if we are a client.

        :type server_ip: str
        :type server_port: int
        :type is_root: bool
        :type root_address: tuple
        """
        self.stream = Stream(server_ip, server_port)
        self.packet_factory = PacketFactory()
        self.user_interfarce = UserInterface()
        self.server_ip = SemiNode.parse_ip(server_ip)
        self.server_port = SemiNode.parse_port(server_port)
        self.is_root = is_root
        # self.root_address = (SemiNode.parse_ip(root_address[0]), SemiNode.parse_port(root_address[1]))

        self.neighbours = []
        if self.is_root:
            self.root_node = GraphNode(self.root_address)
            self.network_graph = NetworkGraph(self.root_node)
            self.reunions_arrival_time = dict()
        else:
          #  self.graph_node = GraphNode((server_ip, server_port))
            self.reunion_mode = None
            self.last_reunion_sent_time = None
        self.t = threading.Thread(target=self.run_reunion_daemon)

    def start_user_interface(self):
        """
        For starting UserInterface thread.

        :return:
        """
        self.user_interfarce.run()
        t = threading.Thread(target=self.handle_user_interface_buffer)
        t.run()

    def handle_user_interface_buffer(self):
        """
        In every interval, we should parse user command that buffered from our UserInterface.
        All of the valid commands are listed below:
            1. Register:  With this command, the client send a Register Request packet to the root of the network.
            2. Advertise: Send an Advertise Request to the root of the network for finding first hope.
            3. SendMessage: The following string will be added to a new Message packet and broadcast through the network.

        Warnings:
            1. Ignore irregular commands from the user.
            2. Don't forget to clear our UserInterface buffer.
        :return:
        """
        while(1):
            if self.user_interfarce.buffer == 'Register':
                pass
            elif self.user_interfarce.buffer == 'Advertise':
                pass
            elif self.user_interfarce.buffer[:11] == 'SendMessage':
                pass
            else:
                print("command not supported")
            time.sleep(1)

    def run(self):
        """
        The main loop of the program.

        Code design suggestions:
            1. Parse server in_buf of the stream.
            2. Handle all packets were received from our Stream server.
            3. Parse user_interface_buffer to make message packets.
            4. Send packets stored in nodes buffer of our Stream object.
            5. ** sleep the current thread for 2 seconds **

        Warnings:
            1. At first check reunion daemon condition; Maybe we have a problem in this time
               and so we should hold any actions until Reunion acceptance.
            2. In every situation checkout Advertise Response packets; even is Reunion in failure mode or not

        :return:


        """
        while True:

            if self.is_root or (not self.is_root and not (
                            self.reunion_mode == "pending" and datetime.now() - self.last_reunion_sent_time > timedelta(
                        seconds=4))):
                for buffer in self.stream.read_in_buf():
                    packet = self.packet_factory.parse_buffer(buffer)
                    self.handle_packet(packet)

                # TODO: user interface buffer parse
                self.start_user_interface()

                self.stream.send_out_buf_messages()
            elif not self.is_root and self.reunion_mode == "pending" and datetime.now() - self.last_reunion_sent_time > timedelta(
                    seconds=4):
                for buffer in self.stream.read_in_buf():
                    packet = self.packet_factory.parse_buffer(buffer)
                    if packet.get_type() == 2 and packet.get_res_or_req() == "RES":
                        self.__handle_advertise_packet(packet)
            time.sleep(2)

        pass

    def run_reunion_daemon(self):
        """

        In this function, we will handle all Reunion actions.

        Code design suggestions:
            1. Check if we are the network root or not; The actions are identical.
            2. If it's the root Peer, in every interval check the latest Reunion packet arrival time from every node;
               If time is over for the node turn it off (Maybe you need to remove it from our NetworkGraph).
            3. If it's a non-root peer split the actions by considering whether we are waiting for Reunion Hello Back
               Packet or it's the time to send new Reunion Hello packet.

        Warnings:
            1. If we are the root of the network in the situation that we want to turn a node off, make sure that you will not
               advertise the nodes sub-tree in our GraphNode.
            2. If we are a non-root Peer, save the time when you have sent your last Reunion Hello packet; You need this
               time for checking whether the Reunion was failed or not.
            3. For choosing time intervals you should wait until Reunion Hello or Reunion Hello Back arrival,
               pay attention that our NetworkGraph depth will not be bigger than 8. (Do not forget main loop sleep time)
            4. Suppose that you are a non-root Peer and Reunion was failed, In this time you should make a new Advertise
               Request packet and send it through your register_connection to the root; Don't forget to send this packet
               here, because in the Reunion Failure mode our main loop will not work properly and everything will be got stock!

        :return:
        """

        # TODO: this part is definitely gonna cause a lot of bugs,im not sure with the delays and 4 seconds

        while True:
            if self.is_root:
                for address, last_reunion_time in self.reunions_arrival_time.items():
                    if (datetime.now() - last_reunion_time) > timedelta(seconds=4):
                        self.network_graph.turn_off_node(address)
                        self.network_graph.turn_off_subtree(address)
                        self.network_graph.remove_node(address)
            else:
                if self.reunion_mode == "acceptance":
                    if (datetime.now() - self.last_reunion_sent_time) >= timedelta(seconds=4):
                        nodes_array = [(self.server_ip, self.server_port)]
                        new_packet = self.packet_factory.new_reunion_packet("REQ", (self.server_ip, self.server_port), nodes_array)
                        self.stream.add_message_to_out_buff(self.stream.get_parent_address().get_server_address(),new_packet.get_buf())
                        self.last_reunion_sent_time = datetime.now()
                        self.reunion_mode = "pending"
                elif self.reunion_mode == "pending":
                    if (datetime.now() - self.last_reunion_sent_time) > timedelta(seconds=4):
                        advertise_packet = self.packet_factory.new_advertise_packet("REQ",(self.server_ip, self.server_port))
                        self.stream.add_message_to_out_buff(self.root_address, advertise_packet.get_buf())

    def send_broadcast_packet(self, broadcast_packet):
        """

        For setting broadcast packets buffer into Nodes out_buff.

        Warnings:
            1. Don't send Message packets through register_connections.

        :param broadcast_packet: The packet that should be broadcast through the network.
        :type broadcast_packet: Packet

        :return:
        """
        message = broadcast_packet.get_buf()
        self.stream.add_message_to_all_buffs(message)
        pass

    def handle_packet(self, packet):
        """

        This function act as a wrapper for other handle_###_packet methods to handle the packet.

        Code design suggestion:
            1. It's better to check packet validation right now; For example Validation of the packet length.

        :param packet: The arrived packet that should be handled.

        :type packet Packet

        """
        
        type = packet.get_type()
        if packet.get_version() != 1:
            print("unsupported version", file=sys.stderr)
            raise ValueError
        if type < 1 or type > 5:
            print("unknown packet type", file=sys.stderr)
            raise ValueError

        if type == 1:
            self.__handle_register_packet(packet)
        elif type == 2:
            self.__handle_advertise_packet(packet)
        elif type == 3:
            self.__handle_join_packet(packet)
        elif type == 4:
            self.__handle_message_packet(packet)
        elif type == 5:
            self.__handle_reunion_packet(packet)

    def __check_registered(self, source_address):
        """
        If the Peer is the root of the network we need to find that is a node registered or not.

        :param source_address: Unknown IP/Port address.
        :type source_address: tuple

        :return:
        """
        if self.is_root :
            if self.stream.get_node_by_server(source_address[0],source_address[1]).is_register():
                return True


        pass

    def __handle_advertise_packet(self, packet):
        """
        For advertising peers in the network, It is peer discovery message.

        Request:
            We should act as the root of the network and reply with a neighbour address in a new Advertise Response packet.

        Response:
            When an Advertise Response packet type arrived we should update our parent peer and send a Join packet to the
            new parent.

        Code design suggestion:
            1. Start the Reunion daemon thread when the first Advertise Response packet received.
            2. When an Advertise Response message arrived, make a new Join packet immediately for the advertised address.

        Warnings:
            1. Don't forget to ignore Advertise Request packets when you are a non-root peer.
            2. The addresses which still haven't registered to the network can not request any peer discovery message.
            3. Maybe it's not the first time that the source of the packet sends Advertise Request message. This will happen
               in rare situations like Reunion Failure. Pay attention, don't advertise the address to the packet sender
               sub-tree.
            4. When an Advertise Response packet arrived update our Peer parent for sending Reunion Packets.

        :param packet: Arrived register packet

        :type packet Packet

        :return:
        """

        if packet.get_res_or_req()=="REQ":
            if self.is_root:
                if self.__check_registered(packet.get_source_server_address()):
                    parent=self.__get_neighbour(packet.get_source_server_address())
                    new_packet=self.packet_factory.new_advertise_packet("RES",self.stream.get_server_address(),parent)
                    self.stream.add_message_to_out_buff(packet.get_source_server_address(),new_packet)
                    self.network_graph.add_node(packet.get_source_server_ip(),packet.get_source_server_port(),parent)

        else:
            if not self.is_root:
                buff = packet.get_buf()[23:]
                buff = str(buff)
                buff = buff[2:]
                buff = buff[:len(buff)-1]
                ip = buff[:15]
                port = buff[15:20]
                print(ip, port)
                self.stream.add_node(server_address=(ip, int(port)))
                self.stream.get_parent_node()\
                    .add_message_to_out_buff(PacketFactory.new_join_packet(self.stream.get_server_address()))
                print(self.stream.get_parent_node().out_buff)
                self.stream.get_parent_node().send_message()
                self.t.run()

    def __handle_register_packet(self, packet):
        """
        For registration a new node to the network at first we should make a Node with stream.add_node for'sender' and
        save it.

        Code design suggestion:
            1.For checking whether an address is registered since now or not you can use SemiNode object except Node.

        Warnings:
            1. Don't forget to ignore Register Request packets when you are a non-root peer.

        :param packet: Arrived register packet
        :type packet Packet
        :return:
        """
        #TODO:check this again
        if self.is_root:
            if not self.__check_registered(packet.get_source_server_address()):
                self.stream.add_node(packet.get_source_server_address(),True)
                response_packet=self.packet_factory.new_register_packet("RES",self.stream.get_server_address())
                self.stream.add_message_to_out_buff(packet.get_source_server_address(),response_packet)
        else:
            if packet.get_res_or_req()=="RES":
                advertise_packet=self.packet_factory.new_advertise_packet("REQ",self.stream.get_server_address())
                self.stream.add_message_to_out_buff(packet.get_source_server_address(),advertise_packet)


        pass


    def __check_neighbour(self, address):
        """
        It checks is the address in our neighbours array or not.

        :param address: Unknown address

        :type address: tuple

        :return: Whether is address in our neighbours or not.
        :rtype: bool
        """
        if self.stream.get_node_by_server(address[0], address[1]):
            if not (self.stream.get_node_by_server(address[0], address[1]).is_register()):
                return True

        pass

    def __handle_message_packet(self, packet):
        """
        Only broadcast message to the other nodes.

        Warnings:
            1. Do not forget to ignore messages from unknown sources.
            2. Make sure that you are not sending a message to a register_connection.

        :param packet: Arrived message packet

        :type packet Packet

        :return:
        """
        self.stream.broadcast_to_none_registers(packet.get_buf(), packet.get_source_server_address())

    def __handle_reunion_packet(self, packet):
        """
        In this function we should handle Reunion packet was just arrived.

        Reunion Hello:
            If you are root Peer you should answer with a new Reunion Hello Back packet.
            At first extract all addresses in the packet body and append them in descending order to the new packet.
            You should send the new packet to the first address in the arrived packet.
            If you are a non-root Peer append your IP/Port address to the end of the packet and send it to your parent.

        Reunion Hello Back:
            Check that you are the end node or not; If not only remove your IP/Port address and send the packet to the next
            address, otherwise you received your response from the root and everything is fine.

        Warnings:
            1. Every time adding or removing an address from packet don't forget to update Entity Number field.
            2. If you are the root, update last Reunion Hello arrival packet from the sender node and turn it on.
            3. If you are the end node, update your Reunion mode from pending to acceptance.


        :param packet: Arrived reunion packet
        :return:
        """
#TODO: update number of entire
        res = packet.get_res_or_req()
        body = str(packet.get_buf()[25:])
        ips_str = body[2:len(body) - 1]
        ips = []
        ports = []
        for i in range(0, len(ips_str), 20):
            ips.append(ips_str[i:i + 15])
            ports.append(ips_str[i + 15:i + 20])

        if res == "REQ":
            if self.is_root:
                # updating reunions arrival time
                adds = []
                for i in range(len(ips)):
                    adds.append((SemiNode.parse_port(ips[i]), SemiNode.parse_port(ports[i])))

                for address in adds:
                    self.reunions_arrival_time[address] = datetime.now()

                reversed_ips = ips[::-1]
                reversed_ports = ports[::-1]

                nodes_array = []

                for i in range(len(reversed_ips)):
                    nodes_array.append((reversed_ips[i], reversed_ports[i]))

                new_packet = self.packet_factory.new_reunion_packet("RES", self.stream.get_server_address(),
                                                                    nodes_array)
                node_address=(SemiNode.parse_ip(nodes_array[0][0]), SemiNode.parse_port(nodes_array[0][1]))
                self.stream.add_message_to_out_buff(node_address,new_packet)

            else:

                ips.append(self.stream.get_server_address()[0])
                ports.append(self.stream.get_server_address()[1])

                nodes_array = []

                for i in range(len(ips)):
                    nodes_array.append((ips[i], ports[i]))

                new_packet = self.packet_factory.new_reunion_packet("REQ", self.stream.get_server_address(),
                                                                    nodes_array)
                parent_address=self.stream.get_parent_address.get_server_address()
                self.stream.add_message_to_out_buff(parent_address,new_packet)

        elif res == "RES":
            if ips[len(ips) - 1] == self.stream.get_server_address()[0] \
                    and \
                            ports[len(ports) - 1] == self.stream.get_server_address()[1]:
                ips.pop(len(ips) - 1)
                ports.pop(len(ports) - 1)

                nodes_array = []

                for i in range(len(ips)):
                    nodes_array.append((ips[i], ports[i]))

                new_packet = self.packet_factory.new_reunion_packet("REQ", self.stream.get_server_address(),
                                                                    nodes_array)

                if len(ips) == 0:
                    self.reunion_mode="acceptance"
                else:
                    node_address = (SemiNode.parse_ip(nodes_array[0][0]), SemiNode.parse_port(nodes_array[0][1]))
                    self.stream.add_message_to_out_buff(node_address,new_packet)
                    pass
        pass

    def __handle_join_packet(self, packet):
        """
        When a Join packet received we should add a new node to our nodes array.
        In reality, there is a security level that forbids joining every node to our network.

        :param packet: Arrived register packet.


        :type packet Packet

        :return:
        """
        self.stream.add_node(packet.get_source_server_address(), is_child=True)

    def __get_neighbour(self, sender):
        """
        Finds the best neighbour for the 'sender' from the network_nodes array.
        This function only will call when you are a root peer.

        Code design suggestion:
            1. Use your NetworkGraph find_live_node to find the best neighbour.

        :param sender: Sender of the packet
        :return: The specified neighbour for the sender; The format is like ('192.168.001.001', '05335').
        """
        return self.network_graph.find_live_node(sender)

peer = Peer('127.0.0.1', 65000)

# peer.handle_advertise_packet(PacketFactory.new_advertise_packet('RES', ('192.168.001.001', '65000'), ('192.168.001.001', '65000')))
