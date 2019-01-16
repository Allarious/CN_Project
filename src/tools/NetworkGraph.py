import time


class GraphNode:
    def __init__(self, address):
        self._address = address
        self._children = []

        """

        :param address: (ip, port)
        :type address: tuple

        """
        pass

    def set_parent(self, parent):
        self._parent = parent
        pass

    def turn_off(self):
        self.turned_off = True

    def turn_on(self):
        self.turned_off = False

    def is_truned_off(self):
        return self.turned_off

    def set_address(self, new_address):
        self._address = new_address
        pass

    def get_parent(self):
        return self._parent

    def get_address(self):
        return self._address

    def __reset(self):
        self.set_address(None)

        pass

    def add_child(self, child):
        self._children.append(child)
        pass

    def get_children(self) -> list:
        return self._children


class NetworkGraph:
    def __init__(self, root: GraphNode):
        self.root = root
        root.alive = True
        self.nodes = [root]

    def find_live_node(self, sender):
        current_level = []
        n = None
        current_level.append(self.root)
        while current_level:
            next_level = []
            for node in current_level:
                if len(node.get_children) == 0 or len(node.get_children) == 1:
                    n = node
                    next_level = []
                    break
                else:
                    next_level.append(node.get_children[0])
                    next_level.append(node.get_children[1])
            current_level = next_level
        return n

    """
        Here we should find a neighbour for the sender.
        Best neighbour is the node who is nearest the root and has not more than one child.

        Code design suggestion:
            1. Do a BFS algorithm to find the target.

        Warnings:
            1. Check whether there is sender node in our NetworkGraph or not; if exist do not return sender node or
               any other nodes in it's sub-tree.

        :param sender: The node address we want to find best neighbour for it.
        :type sender: tuple

        :return: Best neighbour for sender.
        :rtype: GraphNode
        """

    def find_node(self, ip, port) -> GraphNode:
        node = None
        for n in self.nodes:
            if n.get_addrress == (ip, port):
                node = n
                break

        return node

    def turn_on_node(self, node_address):
        self.find_node(node_address[0], node_address[1]).turn_on()
        pass

    def turn_off_node(self, node_address):
        self.find_node(node_address[0], node_address[1]).turn_off()

        pass

    def remove_node(self, node_address):
        self.nodes.remove(self.find_node(node_address[0], node_address[1]))
        pass

    def add_node(self, ip, port, father_address):

        new_node = GraphNode((ip, port))
        new_node.set_parent(self.find_node(father_address[0], father_address[1]))
        self.nodes.append(new_node)
        new_node.get_parent().add_child(new_node)

        """ Add a new node with node_address if it does not exist in our NetworkGraph and set its father.

          Warnings:
              1. Don't forget to set the new node as one of the father_address children.
              2. Before using this function make sure that there is a node which has father_address.

          :param ip: IP address of the new node.
          :param port: Port of the new node.
          :param father_address: Father address of the new node

          :type ip: str
          :type port: int
          :type father_address: tuple


          :return:
         """
        pass


