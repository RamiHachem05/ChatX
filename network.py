import socket       
import json         
import threading   
import time         
import os           
import math        
import logging 
from cryptography.fernet import Fernet
class TCPChatClient:
    def __init__(self, username, tcp_port):
        self.username = username
        self.tcp_port = tcp_port
        self.listening = False
        self.listener_thread = None
        self.message_callback = None
        
        # MUTEX LOCK: Critical for thread safety.
        # Since multiple threads might try to modify 'self.active_connections' at the same time, this lock forces them to take turns.
        
        self.lock = threading.Lock()
        
        self.server_socket = None
        
        # This dictionary stores all active open sockets.
        # Key: (IP, Port) tuple. Value: The socket object.
        self.active_connections = {}  # { (ip, port): socket }

        # This key must be the SAME for all clients.
        self.key = b'8P_GkC-1l0j3g5s7q9z1x3c5v7b9n1m3k5j7h9g1f3d=' 
        self.cipher = Fernet(self.key)

        print(f"DEBUG: My Encryption Key is {self.key}")

    #Encrypting the message
    def encrypt_message(self, message):
        return self.cipher.encrypt(message.encode()).decode()
    
    #Decrypting the message
    def decrypt_message(self, encrypted_message):
        try:
            return self.cipher.decrypt(encrypted_message.encode()).decode()
        except:
            return "[Decryption Failed]"
        
    def start_listener(self):
        """Start a TCP server to listen for incoming connections."""
        # Create a TCP/IP socket (IPv4, Stream/TCP)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
        # BIND: Reserve the specific port (e.g., 5001) on this machine.
        self.server_socket.bind(('127.0.0.1', self.tcp_port))
        
        # LISTEN: Tell the OS to start accepting connections on this port.
        # '5' is the backlog (queue size).
        self.server_socket.listen(5)
        
        self.listening = True
        
        # Spawn a background thread to handle the 'accept()' loop.
        # We use a thread so the Main GUI doesn't freeze while waiting for people to call us.
        self.listener_thread = threading.Thread(target=self.listen_for_connections)
        self.listener_thread.daemon = True # Thread dies if the app closes
        self.listener_thread.start()
        print(f"[*] TCP listener started on port {self.tcp_port}")
    
    def listen_for_connections(self):
        """Listen for incoming connections and spawn threads to handle them."""
        while self.listening:
            try:
                # ACCEPT: This line BLOCKS (waits) until a peer connects.
                # It returns a NEW socket object specifically for that peer.
                client_socket, client_address = self.server_socket.accept()
                print(f"[+] New incoming TCP connection from {client_address}")
                
                # SAFETY: Lock the dictionary before adding the new connection.
                with self.lock:
                    self.active_connections[client_address] = client_socket
                    print(f"[*] Stored incoming connection. Active: {list(self.active_connections.keys())}")

                # Create a NEW thread specifically for this one peer.
                # This ensures we can listen to Peer A, Peer B, and Peer C all at the same time.
                conn_thread = threading.Thread(
                    target=self.handle_connection,
                    args=(client_socket, client_address)
                )
                conn_thread.daemon = True
                conn_thread.start()
                
            except Exception as e:
                if self.listening:
                    print(f"[!] Error accepting TCP connection: {e}")
    
    def handle_connection(self, client_socket, client_address):
        """Handle messages from a specific connection."""
        try:
            # Infinite loop to constantly listen for messages from this specific peer
            while True:
                # RECV: Block and wait for data. Read up to 4096 bytes.
                data = client_socket.recv(4096).decode('utf-8')
                
                # If recv returns empty data, it means the other side closed the connection.
                if not data:
                    print(f"[-] Connection closed by peer {client_address}")
                    break
                
                try:
                    # Deserialize JSON string back to Python Dictionary
                    message = json.loads(data)
                    
                    
                    # The content coming in is encrypted. We must unlock it.
                    encrypted_content = message.get("content", "")
                    decrypted_content = self.decrypt_message(encrypted_content)
                    
                    # Update the message object with the readable text
                    message["content"] = decrypted_content

                    print(f"[*] Received message from {client_address}: {message}")

                    sender = message.get("sender", "Unknown")
                    content = message.get("content", "")
                    logging.info(f"[CHAT RECEIVED] From {sender} ({client_address}): {content}")

                    
                    # Notify the GUI (via the callback function in client.py)
                    if self.message_callback:
                        self.message_callback(message, client_address)
                except json.JSONDecodeError:
                    print("[-] Received invalid JSON message")
        except Exception as e:
            print(f"[!] Error handling connection from {client_address}: {e}")
        finally:
            # CLEANUP: If the loop breaks (error or disconnect), remove them from the list.
            with self.lock:
                if client_address in self.active_connections:
                    del self.active_connections[client_address]
                    print(f"[*] Removed connection for {client_address}. Active: {list(self.active_connections.keys())}")
            try:
                client_socket.close()
            except:
                pass
    
    def connect_to_peer(self, peer_ip, peer_port):
        """Connect to a peer's TCP server."""
        peer_address = (peer_ip, peer_port)
        try:
            # CHECK: Do we already have an open line to this person?
            if peer_address in self.active_connections:
                print(f"[!] Already connected to {peer_address}")
                return True

            # CREATE: Make a NEW socket.
            # Note: We do NOT bind this socket. The OS assigns a random ephemeral port (e.g., 54321).
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # CONNECT: Dial the peer's listening port (e.g., 5001).
            peer_socket.connect(peer_address)
            print(f"[+] Successfully connected to peer at {peer_address}")
            
            # STORE: Save this socket so we can send messages through it later.
            with self.lock:
                self.active_connections[peer_address] = peer_socket
                print(f"[*] Stored outgoing connection to {peer_address}. Active: {list(self.active_connections.keys())}")
            
            # LISTEN: Start a thread to listen for REPLIES from this peer.
            # Even though we initiated the call, they can talk back on the same wire.
            conn_thread = threading.Thread(
                target=self.handle_connection,
                args=(peer_socket, peer_address)
            )
            conn_thread.daemon = True
            conn_thread.start()
            
            return True
        except Exception as e:
            print(f"[!] Error connecting to peer {peer_address}: {e}")
            return False
    
    def disconnect(self):
        """Stop listening and close all connections."""
        self.listening = False
        if self.listener_thread:
            self.listener_thread.join(timeout=1)
        
        # Iterate through all open sockets and close them one by one.
        with self.lock:
            for addr, sock in self.active_connections.items():
                try:
                    print(f"[*] Closing connection to {addr}")
                    sock.close()
                except:
                    pass
            self.active_connections.clear()
        
        # Close the main listening socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
    
    def send_message(self, message, peer_address):
        """Send a message to a specific peer."""
        #Encrypting the message before sending it
        encrypted_content = self.encrypt_message(message)

        # Construct the message payload
        message_data = {
            "sender": self.username,
            "timestamp": time.time(),
            "content": encrypted_content
        }
        # Serialize to JSON -> Encode to Bytes
        message_json = json.dumps(message_data).encode('utf-8')
        
        with self.lock:
            # Look up the socket for this specific peer
            if peer_address in self.active_connections:
                try:
                    print(f"[*] Sending message to {peer_address}: {message}")
                    # SEND: Push bytes through the TCP pipe
                    self.active_connections[peer_address].send(message_json)

                    logging.info(f"[CHAT SENT] To {peer_address}: {message}")

                    return True
                except Exception as e:
                    print(f"[!] Error sending message to {peer_address}: {e}")
                    # If sending fails, assume the connection is dead and remove it.
                    del self.active_connections[peer_address]
                    return False
            else:
                print(f"[!] No active connection to {peer_address}. Cannot send.")
                print(f"[*] Current active connections: {list(self.active_connections.keys())}")
                return False
    
    def set_message_callback(self, callback):
        self.message_callback = callback


class UDPFileTransfer:
    def __init__(self, username, udp_port):
        self.username = username
        self.udp_port = udp_port
        
        # Create a UDP socket (SOCK_DGRAM = Datagram/UDP)
        # UDP is connectionless. We don't "connect", we just "sendto" and "recvfrom".
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', udp_port))
        
        self.listening = False
        self.listener_thread = None
        self.file_callback = None
        self.lock = threading.Lock()
        self.chunk_size = 4096 
        
        # Download directory setup
        self.download_dir = "downloads"
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
            print(f"[*] Created directory: {self.download_dir}/")
    
    def start_listening(self):
        self.listening = True
        # Start the background thread that waits for incoming file packets
        self.listener_thread = threading.Thread(target=self.listen_for_files)
        self.listener_thread.daemon = True
        self.listener_thread.start()
    
    def listen_for_files(self):
        while self.listening:
            try:
                # recvfrom: Waits for a UDP packet. 
                # Returns (data_bytes, sender_address_tuple)
                # We read chunk_size + 1024 to account for the header padding.
                data, addr = self.socket.recvfrom(self.chunk_size + 1024)

                try:
                    # PARSING LOGIC:
                    # The protocol adds 1024 bytes of header space padded with nulls (\0).
                    # We grab the first 1024 bytes, split at the first null, and decode JSON.
                    header_raw = data[:1024].split(b'\0', 1)[0].decode('utf-8', errors='ignore')
                    header = json.loads(header_raw)

                    # CASE 1: New File Incoming
                    if header.get("type") == "file_header":
                        filename = header.get("filename")
                        filesize = header.get("filesize")
                        chunks = header.get("chunks")

                        print(f"[*] File header received from {addr}: "
                              f"filename={filename}, size={filesize}, chunks={chunks}")
                        
                        # Notify GUI: "Transfer Started"
                        with self.lock:
                            if self.file_callback:
                                self.file_callback("start", filename, filesize, 0, addr)
                        
                        # Prepare file paths
                        temp_filepath = os.path.join(self.download_dir, f"temp_{filename}")
                        final_filepath = os.path.join(self.download_dir, filename)
                        print(f"[*] Will save incoming file to: {os.path.abspath(final_filepath)}")
                        
                        received_chunks = 0
                        
                        # Loop to receive the exact number of chunks expected
                        with open(temp_filepath, 'wb') as f:
                            while received_chunks < chunks:
                                data, _ = self.socket.recvfrom(self.chunk_size + 1024)
                                try:
                                    # Parse packet header again
                                    chunk_header_raw = data[:1024].split(b'\0', 1)[0].decode('utf-8', errors='ignore')
                                    chunk_header = json.loads(chunk_header_raw)

                                    if chunk_header.get("type") == "file_chunk":
                                        # Extract the raw binary data (everything after the first 1024 bytes)
                                        chunk_data = data[1024:]
                                        f.write(chunk_data)
                                        received_chunks += 1
                                        
                                        # Notify GUI of progress
                                        with self.lock:
                                            if self.file_callback:
                                                progress = (received_chunks / chunks) * 100
                                                self.file_callback("progress", filename, filesize, progress, addr)
                                except json.JSONDecodeError:
                                    # Invalid chunk header, ignore
                                    continue
                        
                        # Transfer Done: Rename temp file to real filename
                        os.rename(temp_filepath, final_filepath)
                        
                        # Notify GUI: "Transfer Complete"
                        with self.lock:
                            if self.file_callback:
                                self.file_callback("complete", filename, filesize, 100, addr)

                        print(f"[+] File '{filename}' saved to '{os.path.abspath(final_filepath)}'")
                        
                except json.JSONDecodeError:
                    # Not a valid header packet
                    continue

            except Exception as e:
                if self.listening:
                    print(f"[!] Error receiving file: {e}")
    
    def send_file(self, filename, peer_ip, peer_port):
        """Starts the file sending process in a new thread."""
        try:
            if not os.path.exists(filename):
                return False, "File not found"
            
            # Use a thread so large files don't freeze the GUI
            send_thread = threading.Thread(
                target=self._send_file_worker,
                args=(filename, peer_ip, peer_port)
            )
            send_thread.daemon = True
            send_thread.start()
            
            return True, "File transfer started in background."
        except Exception as e:
            return False, f"Error starting file transfer: {e}"

    def _send_file_worker(self, filename, peer_ip, peer_port):
        """Worker thread that handles the actual file sending."""
        try:
            base_filename = os.path.basename(filename)
            filesize = os.path.getsize(filename)
            # Calculate how many pieces we need to send
            chunks = (filesize + self.chunk_size - 1) // self.chunk_size ##Like a Ceil Function
            
            
            # STEP 1: Send the File Header (Meta-data)
            header = {
                "type": "file_header",
                "filename": base_filename,
                "filesize": filesize,
                "chunks": chunks,
                "sender": self.username
            }
            header_data = json.dumps(header).encode('utf-8')
            # Pad the header to exactly 1024 bytes using null characters (\0)
            # This ensures the receiver knows exactly where the header ends.
            header_data = header_data.ljust(1024, b'\0')
            self.socket.sendto(header_data, (peer_ip, peer_port))
            
            # STEP 2: Read file and send chunks
            with open(filename, 'rb') as f:
                chunk_index = 0
                while True:
                    # Read 4KB of binary data
                    chunk_data = f.read(self.chunk_size)
                    if not chunk_data:
                        break
                    
                    # Create chunk header
                    chunk_header = {
                        "type": "file_chunk",
                        "index": chunk_index,
                        "sender": self.username
                    }
                    header_bytes = json.dumps(chunk_header).encode('utf-8')
                    header_bytes = header_bytes.ljust(1024, b'\0')
                    
                    # Combine Header + Binary Data
                    packet = header_bytes + chunk_data
                    
                    # Blast it via UDP
                    self.socket.sendto(packet, (peer_ip, peer_port))
                    chunk_index += 1
            
        except Exception as e:
            print(f"[!] Error in file sending thread: {e}")
    
    def set_file_callback(self, callback):
        self.file_callback = callback
    
    def stop_listening(self):
        self.listening = False
        if self.listener_thread:
            self.listener_thread.join(timeout=1)
        try:
            self.socket.close()
        except:
            pass


class ServerConnector:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        # Create TCP socket for registry communication
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self):
        try:
            # Persistent connection to the Central Server
            self.socket.connect((self.server_host, self.server_port))
            return True
        except Exception as e:
            print(f"[!] Error connecting to server: {e}")
            return False
    
    def disconnect(self):
        try:
            self.socket.close()
        except:
            pass
    
    def register(self, username, tcp_port, udp_port):
        try:
            # Construct JSON command to tell server who we are
            request = {
                "command": "register",
                "username": username,
                "tcp_port": tcp_port,
                "udp_port": udp_port
            }
            ##Sending the request to the server
            self.socket.send(json.dumps(request).encode('utf-8')) 
            # Wait for confirmation response
            response = json.loads(self.socket.recv(1024).decode('utf-8')) ##Getting the response back from the server.
            return response.get("status") == "success"
        except Exception as e:
            print(f"[!] Error registering with server: {e}")
            return False
    
    def get_peers(self):
        try:
            # Ask server for list of active users
            request = {"command": "get_peers"}
            self.socket.send(json.dumps(request).encode('utf-8'))
            # Receive larger buffer (4096) as peer list might be long
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            if response.get("status") == "success":
                return response.get("peers", {})
            return {}
        except Exception as e:
            print(f"[!] Error getting peers from server: {e}")
            return {}
    
    def unregister(self, username):
        try:
            # Tell server to remove us from the list
            request = {"command": "unregister", "username": username}
            self.socket.send(json.dumps(request).encode('utf-8'))
            response = json.loads(self.socket.recv(1024).decode('utf-8'))
            return response.get("status") == "success"
        except Exception as e:
            print(f"[!] Error unregistering from server: {e}")
            return False