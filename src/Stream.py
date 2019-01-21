from src.tools.simpletcp.tcpserver import TCPServer

from src.tools.Node import Node
from threading import Thread
import threading
from time import sleep


class Stream:

    def __init__(self, ip, port):
        """
        The Stream object constructor.

        Code design suggestion:
            1. Make a separate Thread for your TCPServer and start immediately.


        :param ip: 15 characters
        :param port: 5 characters
        """

        self.ip = Node.parse_ip(ip)
        self.port = Node.parse_port(port)

        self._server_in_buf = []

        self.nodes = []
        self.nodes_is_parent = []

        def callback(address, queue, data):
            """
            The callback function will run when a new data received from server_buffer.

            :param address: Source address.
            :param queue: Response queue.
            :param data: The data received from the socket.
            :return:
            """
            print(data)
            queue.put(bytes('ACK', 'utf8'))
            self._server_in_buf.append(data)
            print(self._server_in_buf)

        tcp_server = TCPServer(self.ip, port, callback)

        # creating thread
        t1 = threading.Thread(target=tcp_server.run)
        # starting thread 2
        t1.start()

    def get_server_address(self):
        """

        :return: Our TCPServer address
        :rtype: tuple
        """
        return self.ip, self.port

    def clear_in_buff(self):
        """
        Discard any data in TCPServer input buffer.

        :return:
        """
        self._server_in_buf.clear()

    def add_node(self, server_address, set_register_connection=False, is_child=False):
        """
        Will add new a node to our Stream.

        :param server_address: New node TCPServer address.
        :param set_register_connection: Shows that is this connection a register_connection or not.

        :type server_address: tuple
        :type set_register_connection: bool

        :return:
        """
        self.nodes.append(Node(server_address, set_register_connection))
        if is_child and not set_register_connection:
            self.nodes_is_parent.append(0)
        else:
            self.nodes_is_parent.append(1)

    def remove_node(self, node):
        """
        Remove the node from our Stream.

        Warnings:
            1. Close the node after deletion.

        :param node: The node we want to remove.
        :type node: Node

        :return:
        """

        for i in range(0, len(self.nodes)):
            if self.nodes[i] == node:
                self.nodes.pop(i)
                self.nodes_is_parent.pop(i)
                node.close()

    def get_node_by_server(self, ip, port):
        """

        Will find the node that has IP/Port address of input.

        Warnings:
            1. Before comparing the address parse it to a standard format with Node.parse_### functions.

        :param ip: input address IP
        :param port: input address Port

        :return: The node that input address.
        :rtype: Node
        """
        for node in self.nodes:
            if node.get_server_address() == (node.parse_ip(ip), node.parse_port(port)):
                return node


    def add_message_to_out_buff(self, address, message):
        """
        In this function, we will add the message to the output buffer of the node that has the input address.
        Later we should use send_out_buf_messages to send these buffers into their sockets.

        :param address: Node address that we want to send the message
        :param message: Message we want to send

        Warnings:
            1. Check whether the node address is in our nodes or not.

        :return:
        """
        for node in self.nodes:
            if node.get_server_address() == node.parse_address(address):
                node.add_message_to_out_buff(message)
                break

    def add_message_to_all_buffs(self,message):
        for node in self.nodes:
            if(not(node.is_register())):
                node.add_message_to_out_buff(message)

    def read_in_buf(self):
        """
        Only returns the input buffer of our TCPServer.

        :return: TCPServer input buffer.
        :rtype: list
        """
        return self._server_in_buf

    def send_messages_to_node(self, node):
        """
        Send buffered messages to the 'node'

        Warnings:
            1. Insert an exception handler here; Maybe the node socket you want to send the message has turned off and
            you need to remove this node from stream nodes.

        :param node:
        :type node Node

        :return:
        """
        try:
            node.send_message()
        except:
            self.remove_node(node)

    def send_out_buf_messages(self, only_register=False):
        """
        In this function, we will send hole out buffers to their own clients.

        :return:
        """
        for node in self.nodes:
            if only_register:
                if node.register:
                    self.send_messages_to_node(node)
            else:
                self.send_messages_to_node(node)


    def broadcast_to_none_registers(self, message):


        """ this function broadcasts the given message to none registered nodes """

        for node in self.nodes:
            if not node.register:
                node.out_buff.clear()
                node.add_message_to_out_buff(message)
                node.send_message()



#Tests
#build a stream, node and info via node

# stream = Stream('127.0.0.1', 61321)
# node = Node(('127.0.0.1', 61321), False)
#
# node.add_message_to_out_buff("preni")
# print(node.send_message())
# node.add_message_to_out_buff("yoho")
# print(node.send_message())
# node.add_message_to_out_buff("jam it out")
# print(node.send_message())
# node.add_message_to_out_buff("hi hi")
# print(node.send_message())