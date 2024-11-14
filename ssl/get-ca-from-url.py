#!/usr/bin/env python

# This script will download the CA certificate from the given URL and save it to a file.  The file will be saved in the same directory as the script and will be named "ca.pem".  The purpose of the downloaded CA is so that it can be used to verify the server's certificate when making an HTTPS request.  This is useful when the server's certificate is signed by a CA that is not in the system's trust store.  This script will be ran from the command line with the URL as an argument.

import sys
import socket
import ssl
from urllib.parse import urlparse
import os
import subprocess
import tempfile

def get_cert_chain_using_openssl(hostname, port=443):
    """
    Use openssl command line tool to get the full certificate chain
    
    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default 443)
        
    Returns:
        list: List of certificates in PEM format
    """
    try:
        # Use openssl s_client to get the full chain
        cmd = [
            'openssl', 's_client',
            '-connect', f'{hostname}:{port}',
            '-showcerts',
            '-servername', hostname
        ]
        
        # Create a temporary file for the certificates
        with tempfile.NamedTemporaryFile(mode='w+b') as f:
            # Write a newline to stdin to complete the connection
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate(input=b'\n')
            
            if process.returncode != 0:
                raise ValueError(f"OpenSSL error: {stderr.decode()}")
            
            # Parse the output to extract certificates
            certs = []
            current_cert = []
            stdout = stdout.decode('utf-8')
            
            in_cert = False
            for line in stdout.split('\n'):
                if '-----BEGIN CERTIFICATE-----' in line:
                    in_cert = True
                    current_cert = [line]
                elif '-----END CERTIFICATE-----' in line:
                    in_cert = False
                    current_cert.append(line)
                    certs.append('\n'.join(current_cert))
                elif in_cert:
                    current_cert.append(line)
            
            if not certs:
                raise ValueError("No certificates found in the chain")
                
            # Print information about each certificate
            print(f"\nFound {len(certs)} certificates in the chain:")
            for i, cert in enumerate(certs):
                # Use openssl to get certificate details
                with tempfile.NamedTemporaryFile(mode='w') as cert_file:
                    cert_file.write(cert)
                    cert_file.flush()
                    
                    cmd = ['openssl', 'x509', '-in', cert_file.name, '-noout', '-subject', '-issuer']
                    process = subprocess.run(cmd, capture_output=True, text=True)
                    
                    print(f"\nCertificate {i+1}:")
                    print(process.stdout.strip())
            
            # Return the root CA certificate (last in chain)
            return certs[-1]
            
    except subprocess.CalledProcessError as e:
        raise ValueError(f"OpenSSL command failed: {e}")
    except Exception as e:
        raise ValueError(f"Error getting certificate chain: {e}")

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

        print(f"Connecting to {hostname}...")
        
        # Get the CA certificate (last in chain)
        ca_cert = get_cert_chain_using_openssl(hostname)
        
        # Save the certificate
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(script_dir, "ca.pem")
        save_certificate(ca_cert, cert_path)
        
        print(f"\nSuccessfully saved root CA certificate to: {cert_path}")
        return 0

    except ValueError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return 1

if __name__ == "__main__":
    main()