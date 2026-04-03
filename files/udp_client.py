#!/usr/bin/env python3
"""udp_client.py"""
import socket
import time
import sys
import argparse

def send_udp_with_retry(message, address='127.0.0.1', port=5, timeout=1, max_retries=3):
    retries = 0
    response = None
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.settimeout(timeout)
    
    while retries < max_retries:
        try:
            udp_socket.sendto(message.encode(), (address, port))
            response, _ = udp_socket.recvfrom(1024)
            if response:
                response = response.decode()
                break
        except socket.timeout:
            retries += 1
            if retries < max_retries:
                time.sleep(timeout)
    
    udp_socket.close()
    return response

def main():
    parser = argparse.ArgumentParser(description='UDP client for hosts file service')
    parser.add_argument('command', help='Command to send (canon, get, host, disable, save)')
    parser.add_argument('args', nargs='*', help='Command arguments')
    parser.add_argument('--host', default='127.0.0.1', help='UDP server host')
    parser.add_argument('--port', type=int, default=5, help='UDP server port')
    parser.add_argument('--retries', type=int, default=3, help='Number of retries')
    parser.add_argument('--timeout', type=int, default=1, help='Timeout in seconds')
    
    args = parser.parse_args()
    
    # Build the message
    if args.args:
        message = f"{args.command} {' '.join(args.args)}"
    else:
        message = args.command
    
    response = send_udp_with_retry(
        message,
        address=args.host,
        port=args.port,
        timeout=args.timeout,
        max_retries=args.retries
    )
    
    if not response:
        print('ERROR: No response from UDP service', file=sys.stderr)
        sys.exit(1)
    
    response_status = response[0]
    response_msg = response[1:].strip()
    
    # Output in a format easy for Ansible to parse
    print(f"status={response_status}")
    print(f"message={response_msg}")
    
    # Return appropriate exit code
    # For expected responses, exit 0; for errors, exit 1
    expected_responses = {
        'canon': 'L',
        'get': ['D', 'O', 'F'],
        'host': 'U',
        'disable': 'K',
        'save': 'S'
    }
    
    expected = expected_responses.get(args.command)
    if expected:
        if isinstance(expected, list):
            if response_status not in expected:
                sys.exit(1)
        elif response_status != expected:
            sys.exit(1)
    
    sys.exit(0)

if __name__ == '__main__':
    main()
