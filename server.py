# server.py
import socket
import threading
import json
import time

class Server:
    def __init__(self, host='127.0.0.1', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peers = {}  # {username: (ip, port)}
        self.running = False # A control flag to keep the main loop running
        self.lock = threading.Lock() # A mutex used so multiple threads don’t access self.peers at the same time.
    
    def start(self):
        # 1. Bind: Tell the Operating System "I am claiming this IP and Port for this application".
        self.server_socket.bind((self.host, self.port))

        self.server_socket.listen(5)
        self.running = True
        # --- CLARIFIED STARTUP MESSAGE ---
        print(f"*** Server started successfully! ***")
        print(f"Listening for connections on {self.host}:{self.port}")
        print("Waiting for clients to connect...")
        print("---------------------------------")
        
        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept() # 4. Accept: THIS IS A BLOCKING CALL.
                # The code pauses here and waits until a client physically connects.
                # When they do, it returns TWO things:
                # client_socket: A NEW socket object specifically for speaking to this ONE client.
                # client_address: A tuple (IP, Port) identifying the client.
                print(f"[+] New connection from {client_address}")
                # 5. Threading: Create a new thread to handle this specific client.

               
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True # Daemon = True means: If the main program quits, kill this thread immediately.
                # We don't want zombie threads keeping the program alive after we close it.
                client_thread.start()
            except KeyboardInterrupt:
                print("\n[!] Server shutting down...")
                self.stop()
                break
            except Exception as e:
                print(f"[!] Error accepting connections: {e}")
    
    def handle_client(self, client_socket, client_address):
        try:
            while True:
                # 1. Receive Data: Wait for the client to send a message.
                # recv(1024) reads up to 1024 bytes from the network buffer.
                # .decode('utf-8') turns the raw bytes (0s and 1s) into a String.
                data = client_socket.recv(1024).decode('utf-8') 

                # If 'data' is empty, it means the client disconnected/closed the socket.
                if not data:
                    break
                
                try:
                    # 2. Parse JSON: Convert the String '{"command": "register"}' into a Python Dictionary.
                    request = json.loads(data) 

                    # 3. Process: Figure out what they want (Register? Get List?) and get the answer.
                    response = self.process_request(request, client_address)

                    # 4. Send Response: Convert the answer Dictionary back to JSON String -> Bytes -> Send.
                    client_socket.send(json.dumps(response).encode('utf-8'))
                except json.JSONDecodeError:
                    print(f"[-] Invalid JSON from {client_address}")
                    client_socket.send(json.dumps({"status": "error", "message": "Invalid JSON"}).encode('utf-8'))
        except Exception as e:
            print(f"[!] Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            print(f"[-] Connection from {client_address} closed")
    
    def process_request(self, request, client_address):
        command = request.get("command")
        
        if command == "register":
            # Client wants to tell us they are online.
            username = request.get("username")
            tcp_port = request.get("tcp_port")
            udp_port = request.get("udp_port")


            # LOCKING: We are about to write to shared memory (self.peers).
            # If two threads write at once, the dict gets corrupted.
            # 'with self.lock' waits until the lock is free, grabs it, does the work, and releases it.
            
            with self.lock:
                self.peers[username] = {
                    "ip": client_address[0], 
                    "tcp_port": tcp_port,
                    "udp_port": udp_port
                }
            
            print(f"[+] Registered peer: {username} at {client_address[0]}:{tcp_port}/{udp_port}")
            return {"status": "success", "message": "Registered successfully"}
        
        elif command == "get_peers":
            #Client is retreieving his peers
            with self.lock:
                return {"status": "success", "peers": self.peers}
        
        elif command == "unregister":
            # Client is logging off.
            username = request.get("username")
            with self.lock:
                if username in self.peers:
                    del self.peers[username]
            
            print(f"[-] Unregistered peer: {username}")
            return {"status": "success", "message": "Unregistered successfully"}
        
        else:
            return {"status": "error", "message": "Unknown command"}
    
    
    def stop(self):
        # Cleanup function to shut down the server safely.
        self.running = False
        self.server_socket.close() # Close the main door so no new clients can connect.

if __name__ == "__main__":
    server = Server()
    server.start()