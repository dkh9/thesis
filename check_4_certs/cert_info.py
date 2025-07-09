#!/usr/bin/env python3
import sys
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def get_cert_info(cert_path):
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    try:
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_data, default_backend())

    info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, 'X'),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }

    return info

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: cert_info.py <certificate file>", file=sys.stderr)
        sys.exit(1)

    cert_path = sys.argv[1]
    try:
        info = get_cert_info(cert_path)
        print(json.dumps(info, indent=None))  
    except Exception as e:
        print(f"Error processing {cert_path}: {e}", file=sys.stderr)
        sys.exit(2)
