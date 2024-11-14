#!/usr/bin/env python3
import sys
import ssl
import socket
import argparse
import os
from urllib.parse import urlparse
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def get_certificate_chain(hostname, port=443):
    """Fetch the complete certificate chain from a server"""
    try:
        # Create a socket without verification to get the raw chain
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the binary chain
                der_chain = ssock.get_peer_cert_chain()
                
                # Convert to PEM format
                pem_chain = []
                for der_cert in der_chain:
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
                    pem_chain.append(pem)
                
                return pem_chain
    except Exception as e:
        print(f"Error fetching certificate chain: {e}")
        return None

def analyze_cert_chain(chain):
    """Analyze a certificate chain for missing links"""
    if not chain:
        return
        
    print("\nServer Certificate Chain Analysis:")
    print("=" * 60)
    
    for i, cert_pem in enumerate(chain):
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        
        # Determine if it's self-signed
        self_signed = cert.issuer == cert.subject
        
        print(f"\nCertificate #{i+1}:")
        print(f"  Subject: {cert.subject}")
        print(f"  Issuer:  {cert.issuer}")
        print(f"  Self-signed: {'Yes' if self_signed else 'No'}")
        print(f"  Valid until: {cert.not_valid_after_utc}")
        
        # Get basic constraints
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = basic_constraints.value.ca
            print(f"  CA: {is_ca}")
        except x509.extensions.ExtensionNotFound:
            print("  CA: Unknown (no BasicConstraints)")

def check_ca_file(ca_file):
    """Validate and analyze the CA store file"""
    try:
        if not os.path.exists(ca_file):
            print(f"\nError: CA file '{ca_file}' does not exist!")
            return False
            
        if os.path.getsize(ca_file) == 0:
            print(f"\nError: CA file '{ca_file}' is empty!")
            return False
            
        print(f"\nCA Store Analysis:")
        print(f"Path: {os.path.abspath(ca_file)}")
        print(f"Size: {os.path.getsize(ca_file)} bytes")
        
        # Try to parse certificates in the CA store
        with open(ca_file, 'rb') as f:
            ca_data = f.read()
            
        certs = []
        current = []
        in_cert = False
        
        # Parse PEM certificates
        for line in ca_data.decode('utf-8').splitlines():
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                current = [line]
            elif '-----END CERTIFICATE-----' in line:
                in_cert = False
                current.append(line)
                certs.append('\n'.join(current))
            elif in_cert:
                current.append(line)
        
        if not certs:
            print(f"Warning: No valid PEM certificates found in '{ca_file}'")
            return False
            
        print(f"Certificates found: {len(certs)}")
        
        # Analyze each CA certificate
        for i, cert_pem in enumerate(certs, 1):
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            print(f"\nCA Certificate #{i}:")
            print(f"  Subject: {cert.subject}")
            print(f"  Issuer: {cert.issuer}")
            print(f"  Valid until: {cert.not_valid_after_utc}")
            
            # Check if it's a root CA
            is_root = cert.issuer == cert.subject
            print(f"  Root CA: {'Yes' if is_root else 'No'}")
            
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                )
                is_ca = basic_constraints.value.ca
                print(f"  CA: {is_ca}")
            except x509.extensions.ExtensionNotFound:
                print("  CA: Unknown (no BasicConstraints)")
        
        return True
            
    except Exception as e:
        print(f"\nError analyzing CA file: {str(e)}")
        return False

def verify_cert(url, ca_file='./ca.pem'):
    """
    Verify a URL's SSL certificate using a custom CA store
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    # First check the CA store
    if not check_ca_file(ca_file):
        return False
    
    # Fetch and analyze the server's certificate chain
    print(f"\nFetching certificate chain from {hostname}...")
    chain = get_certificate_chain(hostname, port)
    if chain:
        analyze_cert_chain(chain)
    
    print(f"\nAttempting verified connection to {url}")
    print(f"Using CA store: {ca_file}")
    
    try:
        context = ssl.create_default_context(cafile=ca_file)
        print("SSL context created successfully")
    except Exception as e:
        print(f"Error creating SSL context: {e}")
        return False
    
    try:
        print(f"\nConnecting to {hostname}:{port}...")
        with socket.create_connection((hostname, port)) as sock:
            print("TCP connection established, initiating TLS handshake...")
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                print("\nTLS handshake successful!")
                print(f"Using {version} with cipher {cipher[0]} ({cipher[2]} bits)")
                
                print("\nVerified Server Certificate Details:")
                print(f"Subject: {dict(x[0] for x in cert['subject'])}")
                print(f"Issuer: {dict(x[0] for x in cert['issuer'])}")
                print(f"Valid From: {cert['notBefore']}")
                print(f"Valid Until: {cert['notAfter']}")
                
                if 'subjectAltName' in cert:
                    print("\nSubject Alternative Names:")
                    for type_name, value in cert['subjectAltName']:
                        print(f"  {type_name}: {value}")
                
                return True
                
    except ssl.SSLCertVerificationError as e:
        print(f"\nCertificate Validation Failed!")
        print(f"Error: {e}")
        print("\nDiagnosis:")
        print("Your CA store contains the intermediate certificate:")
        print("  GlobalSign Atlas R3 DV TLS CA 2024 Q2")
        print("But is missing the root certificate:")
        print("  GlobalSign Root CA - R3")
        print("\nTo fix this, you need to:")
        print("1. Download the GlobalSign Root CA - R3 certificate")
        print("2. Append it to your ca.pem file")
        print("3. Ensure both certificates are in proper PEM format")
        return False
    except Exception as e:
        print(f"\nUnexpected error occurred!")
        print(f"Error: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Validate SSL certificates using a custom CA store'
    )
    parser.add_argument('url', help='HTTPS URL to validate')
    parser.add_argument(
        '--ca-file', 
        default='./ca.pem',
        help='Path to CA certificate store (default: ./ca.pem)'
    )
    
    args = parser.parse_args()
    
    if not args.url.startswith('https://'):
        print("Error: URL must start with https://")
        sys.exit(1)
        
    verify_cert(args.url, args.ca_file)

if __name__ == "__main__":
    main()