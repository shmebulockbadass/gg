import socket

HOST = "127.0.0.1"  # Localhost (use "0.0.0.0" to accept connections from other devices)
PORT = 65432        # Non-privileged port (> 1023)

def start_server():
    # Create a TCP/IPv4 socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Allow immediate port reuse after closing
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[LISTENING] Server is listening on {HOST}:{PORT}...")

        # Block and wait for an incoming client connection
        conn, addr = server_socket.accept()
        with conn:
            print(f"[CONNECTED] Client connected from {addr}")
            while True:
                data = conn.recv(1024)  # Receive up to 1024 bytes
                if not data:
                    print("[DISCONNECTED] Client closed the connection.")
                    break
                
                message = data.decode("utf-8")
                print(f"[RECEIVED] {message}")
                
                # Send a response back to the client
                reply = f"Server received: {message}"
                conn.sendall(reply.encode("utf-8"))

if __name__ == "__main__":
    start_server()