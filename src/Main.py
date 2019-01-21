from src.Peer import Peer
from src.tools.NetworkGraph import NetworkGraph

if __name__ == "__main__":
    server = Peer("insert IP Address", "Insert Port as Int", is_root=True)
    server.run()

    client = Peer("Insert IP Address", "Insert Port as Int",
                  is_root=False,root_address=("Insert IP Address", "Insert Port as Int"))



