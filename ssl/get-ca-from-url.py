#!/usr/bin/env python

# This script will download the CA certificate from the given URL and save it to a file.  The file will be saved in the same directory as the script and will be named "ca.pem".  The purpose of the downloaded CA is so that it can be used to verify the server's certificate when making an HTTPS request.  This is useful when the server's certificate is signed by a CA that is not in the system's trust store.  This script will be ran from the command line with the URL as an argument.

import sys
import socket
import ssl
import certifi
from urllib.parse import urlparse
import os
import warnings

def extract_server_certificate(hostname, port=443):
    """
    Extract the server's certificate chain from an SSL connection
    
    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default 443)
        
    Returns:
        str: PEM formatted certificate chain
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_binary = ssock.getpeercert(binary_form=True)
            if not cert_binary:
                raise ValueError("No certificate received from server")
            
            # Convert to PEM format
            cert_pem = ssl.DER_cert_to_PEM_cert(cert_binary)
            return cert_pem

def save_certificate(cert_pem, output_path):
    """
    Save the certificate to a file
    
    Args:
        cert_pem (str): The PEM formatted certificate
        output_path (str): Path to save the certificate
    """
    with open(output_path, 'w') as f:
        f.write(cert_pem)

def main():
    if len(sys.argv) != 2:
        print("Usage: python get-ca-from-url.py <hostname>")
        sys.exit(1)
    
    url = sys.argv[1]
    
    try:
        # Parse the URL to get the hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # If hostname is empty, try using the full URL (in case user didn't include protocol)
        if not hostname:
            hostname = url.split('/')[0]
        
        # Remove any port number if present
        hostname = hostname.split(':')[0]
        
        if not hostname:
            raise ValueError("Invalid hostname")

        # Get the certificate
        print(f"Connecting to {hostname}...")
        cert_pem = extract_server_certificate(hostname)
        
        # Save the certificate
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(script_dir, "ca.pem")
        save_certificate(cert_pem, cert_path)
        
        print(f"Successfully saved server certificate to: {cert_path}")
        return 0

    except (socket.gaierror, ConnectionRefusedError) as e:
        print(f"Connection error: {e}")
        return 1
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
        return 1
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    main()