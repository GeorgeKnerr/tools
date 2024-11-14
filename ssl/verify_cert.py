#!/usr/bin/env python3

import sys
import ssl
import socket
import OpenSSL
import argparse
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

def load_ca_cert(ca_path):
    """
    Load the local CA certificate from the specified path.
    Returns both OpenSSL and cryptography certificate objects.
    """
    try:
        with open(ca_path, 'rb') as f:
            ca_cert_data = f.read()
            # Load as OpenSSL certificate for info display
            ca_cert_openssl = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM, 
                ca_cert_data
            )
            # Load as cryptography certificate for validation
            ca_cert_crypto = x509.load_pem_x509_certificate(ca_cert_data)
            
        print("\n=== Local CA Certificate Information ===")
        print(f"Subject: {ca_cert_openssl.get_subject().get_components()}")
        print(f"Issuer: {ca_cert_openssl.get_issuer().get_components()}")
        print(f"Serial Number: {ca_cert_openssl.get_serial_number()}")
        print(f"Not Before: {ca_cert_openssl.get_notBefore()}")
        print(f"Not After: {ca_cert_openssl.get_notAfter()}")
        
        return ca_cert_openssl, ca_cert_crypto
    except Exception as e:
        print(f"Error loading CA certificate: {e}")
        sys.exit(1)

def get_server_certificate(hostname, port=443):
    """
    Retrieve the SSL certificate from the remote server.
    Returns both OpenSSL and cryptography certificate objects.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_binary = ssock.getpeercert(binary_form=True)
            # Load as OpenSSL certificate for info display
            cert_openssl = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1,
                cert_binary
            )
            # Load as cryptography certificate for validation
            cert_crypto = x509.load_der_x509_certificate(cert_binary)
            return cert_openssl, cert_crypto

def verify_cert_chain(hostname, server_cert_openssl, server_cert_crypto, 
                     ca_cert_openssl, ca_cert_crypto):
    """
    Verify the certificate chain using the provided CA certificate.
    Performs both name matching and cryptographic signature verification.
    """
    print("\n=== Server Certificate Information ===")
    print(f"Subject: {server_cert_openssl.get_subject().get_components()}")
    print(f"Issuer: {server_cert_openssl.get_issuer().get_components()}")
    print(f"Serial Number: {server_cert_openssl.get_serial_number()}")
    print(f"Not Before: {server_cert_openssl.get_notBefore()}")
    print(f"Not After: {server_cert_openssl.get_notAfter()}")
    
    # Compare the server cert's issuer with the CA cert's subject
    server_issuer = dict(server_cert_openssl.get_issuer().get_components())
    ca_subject = dict(ca_cert_openssl.get_subject().get_components())
    
    print("\n=== Certificate Chain Analysis ===")
    print(f"Server Certificate Issuer: {server_cert_openssl.get_issuer().get_components()}")
    print(f"CA Certificate Subject: {ca_cert_openssl.get_subject().get_components()}")
    
    print("\n=== Certificate Chain Verification ===")
    print("Step 1: Verifying issuer/subject name match...")
    
    # Check if names match
    if server_issuer != ca_subject:
        print("\n❌ Certificate verification failed!")
        print("The CA certificate is not the direct issuer of the server certificate.")
        print("\nDetailed comparison:")
        print(f"Server certificate issuer fields: {server_issuer}")
        print(f"CA certificate subject fields: {ca_subject}")
        return False
    
    print("✅ Issuer/subject names match.")
    print("\nStep 2: Verifying cryptographic signature...")
    
    try:
        # Get the public key from the CA certificate
        public_key = ca_cert_crypto.public_key()
        
        # Verify the signature
        public_key.verify(
            server_cert_crypto.signature,
            server_cert_crypto.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert_crypto.signature_hash_algorithm
        )
        
        print("✅ Cryptographic signature verification successful!")
        print("\n✅ Overall verification successful!")
        print("The server certificate was cryptographically verified to be signed by the provided CA certificate.")
        return True
        
    except InvalidSignature:
        print("\n❌ Cryptographic signature verification failed!")
        print("Although the names match, the server certificate was NOT signed by the provided CA certificate.")
        return False
    except Exception as e:
        print(f"\n❌ Error during cryptographic verification: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Validate SSL certificate chain using a local CA certificate.'
    )
    parser.add_argument('url', help='The HTTPS URL to validate')
    parser.add_argument(
        '--ca-cert', 
        default='./ca.pem',
        help='Path to the CA certificate (default: ./ca.pem)'
    )
    
    args = parser.parse_args()
    
    # Parse the URL
    parsed_url = urlparse(args.url)
    if parsed_url.scheme != 'https':
        print("Error: URL must use HTTPS scheme")
        sys.exit(1)
    
    hostname = parsed_url.hostname
    
    # Load the local CA certificate
    ca_cert_openssl, ca_cert_crypto = load_ca_cert(args.ca_cert)
    
    # Get the server's certificate
    server_cert_openssl, server_cert_crypto = get_server_certificate(hostname)
    
    # Verify the certificate chain
    verify_cert_chain(hostname, server_cert_openssl, server_cert_crypto, 
                     ca_cert_openssl, ca_cert_crypto)

if __name__ == "__main__":
    main()