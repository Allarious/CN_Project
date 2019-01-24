import time


class GraphNode:
    def __init__(self, address, parent=None, turned_off=False):
        self.address = address
        self.children = []
        self.turned_off = turned_off
        self.parent = parent

        """

        :param address: (ip, port)
        :type address: tuple

        """
        pass

    def set_parent(self, parent):
        self.parent = parent

    def turn_off(self):
        self.turned_off = True

    def turn_on(self):
        self.turned_off = False

    def is_turned_off(self):
        return self.turned_off

    def set_address(self, new_address):
        self.address = new_address

    def get_parent(self):
        return self.parent

    def get_address(self):
        return self.address

    def reset(self):
        self.set_address(None)

    def add_child(self, child):
        self.children.append(child)

    def get_children(self):
        return self.children

    def get_children_num(self):
        return len(self.children)


class NetworkGraph:
    def __init__(self, root: GraphNode):
        self.root = root
        self.root.alive = True
        self.root_address = None
        self.nodes = [root]

    def find_live_node(self, sender):
        father = None
        current_level = []
        current_level.append(self.root)
        while current_level:
            next_level = []
            for node in current_level:
                if self.find_node(sender[0],sender[1]):
                    if node not in self.get_subtree(sender):
                        if not (node.is_turned_off()):
                            if len(node.get_children()) == 0 or len(node.get_children()) == 1:
                                father = node
                                next_level = []
                                break
                            else:
                                next_level.append(node.get_children()[0])
                                next_level.append(node.get_children()[1])
                else:
                    if not (node.is_turned_off()):
                        if len(node.get_children()) == 0 or len(node.get_children()) == 1:
                            father = node
                            next_level = []
                            break
                        else:
                            next_level.append(node.get_children()[0])
                            next_level.append(node.get_children()[1])

            current_level = next_level

        return father.get_address()

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
            if n.get_address() == (ip, port):
                node = n
                break

        return node

    def turn_on_node(self, node_address):
        self.find_node(node_address[0], node_address[1]).turn_on()
        pass

    def turn_off_node(self, node_address):
        self.find_node(node_address[0], node_address[1]).turn_off()
        pass

    def turn_off_subtree(self, removed_node_address):
        removed_node = self.find_node(removed_node_address[0], removed_node_address[1])
        curr_level = removed_node.get_children()
        while curr_level:
            next_level = []
            for node in curr_level:
                self.turn_off_node(node.get_address())
                next_level.extend(node.get_children())

            curr_level = next_level

    def get_subtree(self, node_address):
        curr_level = [self.find_node(node_address[0], node_address[1])]
        subtree = []
        while curr_level:
            next_level = []
            for node in curr_level:
                subtree.append(node)
                next_level.extend(node.get_children())

            curr_level = next_level

        return subtree

    def remove_node(self, node_address):
        node = self.find_node(node_address[0], node_address[1])
        # remove node from its parent's children list
        parent = node.get_parent()
        parent.get_children().remove(node)
        node.reset()
        self.nodes.remove(node)

    def add_node(self, ip, port, father_address):
        new_node = GraphNode((ip, port), self.find_node(father_address[0], father_address[1]))
        # new_node.set_parent(self.find_node(father_address[0], father_address[1]))
        self.nodes.append(new_node)
        # print(new_node.get_parent().get_address())

        self.find_node(father_address[0], father_address[1]).add_child(new_node)

        """ Adda new node with node_address if it does not exist in our NetworkGraph and set its father.

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




root=GraphNode((0,0))
network=NetworkGraph(root)

network.add_node(1,1,root.get_address())
# print(network.nodes)

network.add_node(2,2,network.find_live_node((2,2)))
network.add_node(3,3,network.find_live_node((3,3)))

print(network.get_subtree((1,1)))
network.turn_off_subtree((1,1))



# for node in network.nodes:
#     print("childrern of",node.get_address())
#     for chilf in node.get_children():
#         print(chilf.get_address())
#
#
# for i in network.get_subtree((1,1)):
#     print(i.get_address())
