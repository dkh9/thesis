#!/usr/bin/env python3

import sys
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def load_cert(path):
    with open(path, 'rb') as f:
        data = f.read()
        try:
            cert = x509.load_pem_x509_certificate(data, default_backend())
            is_pem = True
        except ValueError:
            cert = x509.load_der_x509_certificate(data, default_backend())
            is_pem = False
        return cert, data, is_pem

def extract_raw_cert_bytes(data, is_pem):
    if is_pem:
        # extract only base64-encoded body
        body = data.decode().split("-----BEGIN CERTIFICATE-----")[1].split("-----END CERTIFICATE-----")[0]
        return base64.b64decode("".join(body.strip().splitlines()))
    else:
        return data  # already in DER format

def summarize(cert):
    return {
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': hex(cert.serial_number),
        'not_valid_before': cert.not_valid_before_utc.isoformat(),
        'not_valid_after': cert.not_valid_after_utc.isoformat(),
        'sig_alg': cert.signature_algorithm_oid._name,
        'signature': cert.signature.hex(),
        # optionally add public key hash or summary
    }

def main(cert1_path, cert2_path):
    differ = False
    cert1, raw1, is_pem1 = load_cert(cert1_path)
    cert2, raw2, is_pem2 = load_cert(cert2_path)

    #print(f"    Comparing:\n  {cert1_path}\n  {cert2_path}\n")

    # Compare parsed fields
    meta1 = summarize(cert1)
    meta2 = summarize(cert2)
    for key in meta1:
        if meta1[key] != meta2[key]:
            #print(f"[!] {key} differs:")
            #print(f"    - {cert1_path}: {meta1[key]}")
            #print(f"    - {cert2_path}: {meta2[key]}\n")
            differ = True

    # Compare raw cert body
    body1 = extract_raw_cert_bytes(raw1, is_pem1)
    body2 = extract_raw_cert_bytes(raw2, is_pem2)

    if body1 != body2:
        #print(f"[!] Raw certificate contents differ (not visible in parsed metadata)\n")
        differ = True

    if differ:
        pass
        #return 0
        #print("0")
        #print("\n--------------\n Final conclusion: different!\n")
    else:
        pass
        #return 1
        #print("1")
        #print("\n--------------\n Final conclusion: same!\n")
    return differ


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: certdiff.py <cert1.pem/der> <cert2.pem/der>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
