# client.py
import sys
import os
import threading
import time
import socket
from PyQt5.QtWidgets import QApplication, QMessageBox, QInputDialog
from gui import MainWindow, SignalHandler
from network import TCPChatClient, UDPFileTransfer, ServerConnector
import logging

class ChatXClient:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.main_window = MainWindow()
        self.signal_handler = self.main_window.signal_handler
        
        # Set the client reference in the main window BEFORE initializing other components
        self.main_window.client = self
        
        # Network components
        self.tcp_port = self.find_free_port()
        self.udp_port = self.find_free_port()
        self.username = ""
        self.server_connector = None
        self.udp_transfer = None
        self.tcp_client = None
        
        # Start the application
        self.init_client()
    
    def find_free_port(self):
        #Letting the OS choose a port and port is automatically closed
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
           # s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def init_client(self):
        # Get username
        username, ok = QInputDialog.getText(None, "Login", "Enter your username:")
        if not ok or not username:
            QMessageBox.critical(None, "Error", "Username is required")
            sys.exit(1)
        
        self.username = username

        # Configure logging to save to a file
        logging.basicConfig(
            filename=f'chat_log_{self.username}.txt', # Creates a file like "chat_log_Alice.txt"
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        logging.info(f"=== Session Started for {self.username} ===")
        
        # --- HARDCODED SERVER DETAILS ---
        server_host = "127.0.0.1"
        server_port = 5000
        
        print(f"[*] Connecting to server at {server_host}:{server_port}...")

        # Connect to server
        self.server_connector = ServerConnector(server_host, server_port)
        if not self.server_connector.connect():
            QMessageBox.critical(None, "Connection Error", 
                                f"Failed to connect to server at {server_host}:{server_port}.\n"
                                "Please ensure the server is running first!")
            sys.exit(1)
        
        print("[+] Successfully connected to server.")
        
        # Register with server
        if not self.server_connector.register(self.username, self.tcp_port, self.udp_port):
            QMessageBox.critical(None, "Error", "Failed to register with server")
            sys.exit(1)
        
        print(f"[*] Registered as '{self.username}' with TCP port {self.tcp_port} and UDP port {self.udp_port}")

        # Initialize TCP client and start listening
        self.tcp_client = TCPChatClient(self.username, self.tcp_port)
        self.tcp_client.set_message_callback(self.message_callback)
        self.tcp_client.start_listener()
        
        # Initialize UDP file transfer
        self.udp_transfer = UDPFileTransfer(self.username, self.udp_port)
        self.udp_transfer.set_file_callback(self.file_callback)
        self.udp_transfer.start_listening()
        
        # Update the file widget with the UDP transfer object
        self.main_window.file_widget.udp_transfer = self.udp_transfer
        
        # Start peer list refresh thread
        self.running = True
        self.refresh_thread = threading.Thread(target=self.refresh_peer_list_periodically)
        self.refresh_thread.daemon = True
        self.refresh_thread.start()
        
        # Initial peer list refresh
        self.refresh_peer_list()
        
        # Show the main window
        self.main_window.show()
    
    def refresh_peer_list(self):
        """Manually refresh the peer list"""
        try:
            peers = self.server_connector.get_peers()
            print(f"[*] Retrieved peer list: {peers}")
            self.signal_handler.peer_list_updated.emit(peers)
            return True
        except Exception as e:
            print(f"[!] Error refreshing peer list: {e}")
            return False
    
    def refresh_peer_list_periodically(self):
        """Periodically refresh the peer list"""
        while self.running:
            try:
                self.refresh_peer_list()
                time.sleep(10)  # Refresh every 10 seconds
            except Exception as e:
                print(f"[!] Error in periodic peer list refresh: {e}")
                time.sleep(5)  # Retry sooner on error
    
    def message_callback(self, message, sender_address):
        """
        Handle incoming messages from peers.
        This method is now simplified: it just emits a signal to the main GUI.
        The GUI (MainWindow) is responsible for all display logic.
        """
        print(f"[*] message_callback: Passing message from {message.get('sender')} to GUI.")
        self.signal_handler.message_received.emit(message, sender_address)
    
    def file_callback(self, status, filename, filesize, progress, addr):
        self.signal_handler.file_update.emit(status, filename, filesize, progress, addr)
    
    # This method is called BY the MainWindow, not the other way around.
    def send_file_to_peer(self, peer_info, file_path):
        if not self.udp_transfer:
            QMessageBox.warning(self.main_window, "Error", "File transfer not initialized")
            return
        
        success, message = self.udp_transfer.send_file(
            file_path, 
            peer_info['ip'], 
            peer_info['udp_port']
        )
        
        if success:
            QMessageBox.information(self.main_window, "File Transfer", message)
        else:
            QMessageBox.warning(self.main_window, "File Transfer Error", message)
    
    def run(self):
        try:
            return self.app.exec_()
        finally:
            self.cleanup()
    
    def cleanup(self):
        self.running = False
        
        # Unregister from server
        if self.server_connector:
            self.server_connector.unregister(self.username)
            self.server_connector.disconnect()
        
        # Stop TCP client
        if self.tcp_client:
            self.tcp_client.disconnect()
        
        # Stop UDP transfer
        if self.udp_transfer:
            self.udp_transfer.stop_listening()
        
        # Wait for threads to finish
        if hasattr(self, 'refresh_thread'):
            self.refresh_thread.join(timeout=1)

if __name__ == "__main__":
    client = ChatXClient()
    sys.exit(client.run())