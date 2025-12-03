# gui.py
import sys
import os
import threading


from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QListWidget, QListWidgetItem, 
                            QTextEdit, QLineEdit, QPushButton, QLabel,
                            QFileDialog, QProgressBar, QStatusBar, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread

class SignalHandler(QObject):
    """
    The 'Mailman' class.
    Since background network threads (TCP/UDP) cannot touch the GUI directly,
    they emit these signals. The Main Thread listens to these signals
    and updates the UI safely.
    """
    # Signal emitted when a chat message arrives. Carries the message dict and sender tuple.
    message_received = pyqtSignal(dict, tuple) 
    
    # Signal emitted during file transfer. Carries status ('start', 'progress'), filename, size, %, address.
    file_update = pyqtSignal(str, str, int, float, tuple) 
    
    # Signal emitted when the background thread fetches a new list of peers.
    peer_list_updated = pyqtSignal(dict)
    
    # Signal to update the small text bar at the bottom of the window.
    status_updated = pyqtSignal(str)

class FileTransferWidget(QWidget):
    """
    A custom component that bundles the File Path input, Browse button,
    Send button, and Progress Bar into one neat widget.
    """
    def __init__(self, udp_transfer, signal_handler, main_window):
        super().__init__(main_window)
        self.udp_transfer = udp_transfer
        self.signal_handler = signal_handler
        self.main_window = main_window
        
        # Build the visual elements
        self.init_ui()
        
        # Listen for file updates (e.g., progress bar movement)
        self.signal_handler.file_update.connect(self.update_file_status)
    
    def init_ui(self):
        # Vertical layout: Stack elements on top of each other
        layout = QVBoxLayout()
        
        # Horizontal layout for the file selection row
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True) 
        
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file) # Connect click to function
        
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(self.browse_button)
        layout.addLayout(file_layout)
        
        self.send_button = QPushButton("Send File")
        self.send_button.clicked.connect(self.send_file)
        layout.addWidget(self.send_button)
        
        # Progress bar starts hidden until a transfer begins
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def browse_file(self):
        # Opens a native OS dialog to pick a file. Returns (path, filter).
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path.setText(file_path)
    
    def send_file(self):
        # Logic to trigger sending. 
        # Note: The actual network logic is inside 'main_window.send_file_to_selected_peer'
        file_path = self.file_path.text()
        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Please select a valid file")
            return
        
        self.main_window.send_file_to_selected_peer(file_path)
    
    def update_file_status(self, status, filename, filesize, progress, addr):
        # This function runs on the Main Thread, triggered by the SignalHandler.
        if status == "start":
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Receiving {filename} from {addr[0]}...")
        elif status == "progress":
            self.progress_bar.setValue(int(progress))
        elif status == "complete":
            self.progress_bar.setValue(100)
            self.status_label.setText(f"Received {filename} successfully")
            QMessageBox.information(self, "File Transfer", f"File {filename} received successfully")

class MainWindow(QMainWindow):
    """
    The main application window.
    Responsible for Layout management and handling User Interactions.
    """
    def __init__(self):
        super().__init__()
        self.signal_handler = SignalHandler()
        self.client = None # Reference to the 'ChatXClient' logic class
        
        # State tracking: Who are we talking to right now?
        self.current_peer = None
        self.current_peer_address = None
        
        # Store chat logs in memory so they don't vanish when switching users
        self.chat_histories = {}  # {peer_name: "html_string"}
        
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("ChatX - Secure Communication Platform")
        self.setGeometry(100, 100, 800, 600) # x, y, width, height
        
        # Central widget is the container for everything inside the window
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget) # Split window Left and Right
        
        # --- LEFT PANEL (Peer List & File Transfer) ---
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        peer_label = QLabel("Online Peers:")
        left_layout.addWidget(peer_label)
        
        # The list of users.
        self.peer_list = QListWidget()
        # Trigger 'select_peer' whenever a user clicks an item in the list
        self.peer_list.itemClicked.connect(self.select_peer)
        left_layout.addWidget(self.peer_list)
        
        refresh_button = QPushButton("Refresh Peers")
        refresh_button.clicked.connect(self.refresh_peers)
        left_layout.addWidget(refresh_button)
        
        # Add the custom File Transfer widget we defined above
        self.file_widget = FileTransferWidget(None, self.signal_handler, self)
        left_layout.addWidget(self.file_widget)
        
        left_panel.setMaximumWidth(300) # Constrain width
        main_layout.addWidget(left_panel)
        
        # --- RIGHT PANEL (Chat History & Input) ---
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        self.chat_title_label = QLabel("Select a peer to start chatting")
        self.chat_title_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        right_layout.addWidget(self.chat_title_label)

        # The Chat History box (Read Only)
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        right_layout.addWidget(self.chat_history)
        
        # Input area (Box + Button)
        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        # Allow pressing 'Enter' key to send
        self.message_input.returnPressed.connect(self.send_message)
        self.message_input.setEnabled(False) # Disabled until a peer is selected
        
        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        self.send_button.setEnabled(False)
        
        input_layout.addWidget(self.message_input)
        input_layout.addWidget(self.send_button)
        right_layout.addLayout(input_layout)

        main_layout.addWidget(right_panel)
        
        # Status Bar (Bottom of window)
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # --- SIGNAL CONNECTIONS ---
        # Connect the 'Mailman' signals to the actual functions that update the UI.
        # This is where the Thread-to-GUI handover happens.
        self.signal_handler.peer_list_updated.connect(self.update_peer_list)
        self.signal_handler.status_updated.connect(self.update_status)
        self.signal_handler.message_received.connect(self.display_incoming_message)
    
    def update_peer_list(self, peers):
        """
        Slot called when background thread finds new peers.
        Refreshes the sidebar list.
        """
        # print(f"[*] Updating peer list with {len(peers)} peers")
        self.peer_list.clear()
        for username, info in peers.items():
            # Don't show ourselves in the list
            if self.client and username != self.client.username:
                # Create a list item
                item = QListWidgetItem(f"{username} ({info['ip']})")
                
                # STORE HIDDEN DATA: We hide the IP/Port inside the item itself using UserRole.
                # This way, when we click it later, we can retrieve the connection info.
                item.setData(Qt.UserRole, info)
                self.peer_list.addItem(item)
                # print(f"[*] Added peer to list: {username} ({info['ip']})")
    
    def update_status(self, message):
        self.status_bar.showMessage(message)
    
    def refresh_peers(self):
        """Manually triggered by the 'Refresh' button"""
        if self.client:
            try:
                # Ask the networking class to fetch peers
                peers = self.client.server_connector.get_peers()
                # Emit signal to update UI (even though we are on main thread, good practice)
                self.signal_handler.peer_list_updated.emit(peers)
                # print("[*] Manually refreshed peer list")
            except Exception as e:
                # print(f"[!] Error refreshing peer list: {e}")
                QMessageBox.warning(self, "Error", f"Failed to refresh peer list: {e}")
    
    def select_peer(self, item):
        """
        Triggered when user clicks a name in the list.
        Initiates the TCP connection logic.
        """
        if not self.client:
            return

        # Retrieve the hidden IP/Port data we stored earlier
        peer_info = item.data(Qt.UserRole)
        peer_name = item.text().split(' ')[0]
        peer_ip = peer_info['ip']
        peer_port = peer_info['tcp_port']
        
        # print(f"[*] Selected peer: {peer_name} at {peer_ip}:{peer_port}")

        if self.current_peer == peer_name:
            return # Already chatting with them

        # Save current chat before switching
        if self.current_peer:
            self.chat_histories[self.current_peer] = self.chat_history.toHtml()

        # Attempt to establish the TCP connection
        if not self.client.tcp_client.connect_to_peer(peer_ip, peer_port):
            QMessageBox.warning(self, "Connection Error", f"Failed to connect to {peer_name}")
            self.peer_list.clearSelection()
            self.current_peer = None
            self.current_peer_address = None
            self.reset_chat_area()
            return

        # Connection successful: Update UI state
        self.current_peer = peer_name
        self.current_peer_address = (peer_ip, peer_port)
        
        self.chat_title_label.setText(f"Chatting with {peer_name}")
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)

        # Restore previous chat history if it exists
        if peer_name in self.chat_histories:
            self.chat_history.setHtml(self.chat_histories[peer_name])
        else:
            self.chat_history.clear()
            self.chat_histories[peer_name] = ""

        self.message_input.setFocus()
        
    def reset_chat_area(self):
        # Clears the right side if connection fails or no peer selected
        self.chat_title_label.setText("Select a peer to start chatting")
        self.chat_history.clear()
        self.message_input.clear()
        self.message_input.setEnabled(False)
        self.send_button.setEnabled(False)

    def send_message(self):
        """Called when 'Send' button is clicked or Enter is pressed"""
        if not self.current_peer or not self.current_peer_address:
            # print("[!] send_message called but no peer is selected.")
            return

        message = self.message_input.text().strip()
        if not message:
            return

        # print(f"[*] Attempting to send message to {self.current_peer} at {self.current_peer_address}: '{message}'")
        
        # Send via TCP Client
        if self.client.tcp_client.send_message(message, self.current_peer_address):
            # print("[+] Message sent successfully.")
            # If successful, show it in our own window
            self.add_message_to_chat(self.current_peer, "You", message)
            
            self.message_input.clear()
        else:
            # print(f"[!] Failed to send message to {self.current_peer}")
            QMessageBox.warning(self, "Error", f"Failed to send message to {self.current_peer}")

    def display_incoming_message(self, message, sender_address):
        """
        Slot called via Signal when a new message arrives from the network.
        """
        sender = message.get("sender", "Unknown")
        content = message.get("content", "")
        # print(f"[*] Received message from {sender}: {content}")

        # Add to history
        self.add_message_to_chat(sender, sender, content)

        # Only update the visual text box if we are looking at that user right now
        if self.current_peer == sender:
            self.chat_history.setHtml(self.chat_histories[sender])

    def add_message_to_chat(self, peer_name, sender, content):
        """Helper to append HTML formatted text to the chat history string"""
        if peer_name not in self.chat_histories:
            self.chat_histories[peer_name] = ""
        
        if sender == "You":
            self.chat_histories[peer_name] += f"<b>You:</b> {content}<br>"
        else:
            self.chat_histories[peer_name] += f"<b>{sender}:</b> {content}<br>"
        
        # Live update if active
        if self.current_peer == peer_name:
            self.chat_history.setHtml(self.chat_histories[peer_name])
    
    def send_file_to_selected_peer(self, file_path):
        """Bridge function to send file to the currently selected peer"""
        if not self.current_peer or not self.current_peer_address:
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer to send the file to")
            return
        
        # Get info of the currently selected row
        current_item = self.peer_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer to send the file to")
            return
        
        # Retrieve the IP/UDP Port from the item's hidden data
        peer_info = current_item.data(Qt.UserRole)
        
        if self.client:
            self.client.send_file_to_peer(peer_info, file_path)

    def closeEvent(self, event):
        """
        PyQt event triggered when the window is being closed (X button).
        We use this to save the current state before the app dies.
        """
        if self.current_peer:
            self.chat_histories[self.current_peer] = self.chat_history.toHtml()
        event.accept()