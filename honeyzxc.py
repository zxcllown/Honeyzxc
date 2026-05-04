#Libraries
import argparse
import sys

from ssh_honeypot import *
from web_honeypot import run_web_honeypot

#Parse Arguments

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)

    parser.add_argument('-s', '--ssh', action= 'store_true')
    parser.add_argument('-w', '--http', action= 'store_true')

    args = parser.parse_args()

    try:
        if args.ssh:
            print("[-] Running SSH Honeypot...")
            honeypot(args.address, args.port, args.username, args.password)
        elif args.http:
            print("[-] Running HTTP Honeypot...")
            if not args.username:
                args.username = 'Administrator'
            if not args.password:
                args.password = 'ZXC'

            print(f"Ports {args.port} and username {args.username} and password {args.password}")
            run_web_honeypot(args.port, args.username, args.password)
        else:
            print("[!] Choose a type of Honeypot...")
    except KeyboardInterrupt:
        print("\n Exiting Honeypot")
        sys.exit(0)
