import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432        # The port used by the server

def start_client():
    # Create a TCP/IPv4 socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((HOST, PORT))
            print(f"[CONNECTED] Connected to server at {HOST}:{PORT}")
            print("Type a message and press Enter (type 'exit' to quit).")

            while True:
                message = input("You: ")
                if message.lower() == "exit":
                    break
                
                # Encode string to bytes and send
                client_socket.sendall(message.encode("utf-8"))
                
                # Wait for and decode the server's reply
                data = client_socket.recv(1024)
                print(f"[SERVER] {data.decode('utf-8')}")
                
        except ConnectionRefusedError:
            print(f"[ERROR] Could not connect to {HOST}:{PORT}. Is the server running?")

if __name__ == "__main__":
    start_client()