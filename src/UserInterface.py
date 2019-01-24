import threading
import time
import pyjs
import webbrowser

class UserInterface(threading.Thread):
    buffer = []

    def run(self):
        """
        Which the user or client sees and works with.
        This method runs every time to see whether there are new messages or not.
        """
        webbrowser.open_new_tab("file:///Users/a11/Desktop/Net_Project/web/index.html")
        while True:
            message = input("Write your command:\n")
            self.buffer.append(message)
            time.sleep(0.5)
