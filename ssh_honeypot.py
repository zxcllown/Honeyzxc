#Libraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import paramiko
import threading

#Constants
logging_format =  logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
#host_key = 'server.key'
host_key = paramiko.RSAKey(filename='server keys/server.key')

#Loggers & Logging Files
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('logs/audits.log', maxBytes=20000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('logs/cmd_audits.log', maxBytes=20000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

#Emulated Shell
def emulated_shell(chan, client_ip):
    chan.send(b'corporate-jumpbox2$ ')
    command = b""
    while True:
        char = chan.recv(1)
        chan.send(char)
        if not char:
            chan.close()

        command += char
        if char == b"\r":
            if command.strip() == b'exit':
                response = b"\nGoodbye!\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
                chan.send(response)
                chan.close()
                break
            elif command.strip() == b'pwd':
                response = b"\n" + b"\\usr\\local" + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            elif command.strip() == b'whoami':
                response = b"\n" + b"corpuser1" + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            elif command.strip() == b'ls':
                response = b"\n" + b"jumpbox1.conf" + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            elif command.strip() == b'cat jumpbox1.conf':
                response = b"\n" + b"Go to zxc.com" + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')
            else:
                response = b"\n" + bytes(command.strip()) + b"\r\n"
                creds_logger.info(f'Command {command.strip()}' + 'executed by ' + f'{client_ip}')

            chan.send(response)
            chan.send(b'corporate-jumpbox2$ ')
            command = b""

#SSH Sever + Sockets

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chaind: int):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        funnel_logger.info(f'Client {self.client_ip} attempted to connection with username: {username} and password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, chan):
        self.event.set()
        return True

    def check_channel_pty_request(self, chan, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, chan, command):
        command = str(command)
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")

    transport = paramiko.Transport(client)

    try:

        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)

        transport.start_server(server=server)

        chan = transport.accept(100)

        if chan is None:
            print("No channel was opened.")

        standard_banner = b"Welcome to Ubuntu 22.04 LTS (Pavel Plekhanov)!\r\n\r\n"
        chan.send(standard_banner)
        emulated_shell(chan, client_ip=client_ip)
    except Exception as error:
        print(error)
        print("!!! ERROR to transport open !!!")
    finally:
        try:
            transport.close()
        except Exception:
            #print(error)
            #print("!!! ERROR to transport.close() !!!")
            pass
        client.close()


#Provision SSH-based Honeypot

def honeypot(address, port, username, password):

    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)
            print("!!! ERROR !!!")
