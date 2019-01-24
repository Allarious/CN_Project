from src.Peer import Peer
from src.tools.NetworkGraph import NetworkGraph

if __name__ == "__main__":
    server = Peer("127.0.0.1", 65055, is_root=True)
    server.run()

    #client = Peer("127.0.0.1", 66001,
    #              is_root=False,root_address=("127.0.0.1", 65000))



