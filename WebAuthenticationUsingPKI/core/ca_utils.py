import os
import datetime
import json
from flask import Blueprint
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

ca_utils_routes = Blueprint("ca_utils", __name__)

# CA PATHS
ROOT_CERT = "ca/root_cert.pem"
ROOT_KEY = "ca/root_key.pem"
INTER_CERT = "ca/inter_cert.pem"
INTER_KEY = "ca/inter_key.pem"
INDEX_PATH = "ca/index.json"

# CA Creation

def create_root_ca():
    # If key already exists, load it
    if os.path.exists(ROOT_KEY):
        with open(ROOT_KEY, "rb") as f:
            root_key = serialization.load_pem_private_key(
                f.read(),
                password=b"Paraphraase",
                backend=default_backend()
            )
        return root_key

    # Generate new root key
    root_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the key
    with open(ROOT_KEY, "wb") as f:
        f.write(root_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"Paraphraase"),
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "pkica.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localpki")]),
        critical=False,
    ).sign(root_key, hashes.SHA256())

    # Save cert
    with open(ROOT_CERT, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return root_key


def create_inter(root_key):
    if os.path.exists(INTER_KEY) and os.path.exists(INTER_CERT):
        # Optional: load and return them if needed
        return None, None

    inter_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Save the key
    with open(INTER_KEY, "wb") as f:
        f.write(inter_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"Paraphraase"),
        ))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, "pkinterca.com"),
    ])

    with open(ROOT_CERT, "rb") as f:
        root_cert_data = f.read()

    root_cert = x509.load_pem_x509_certificate(root_cert_data, default_backend())

    inter_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject
    ).public_key(
        inter_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localinterpki")]),
        critical=False,
    ).sign(root_key, hashes.SHA256())

    # Save intermediate cert
    with open(INTER_CERT, "wb") as f:
        f.write(inter_cert.public_bytes(serialization.Encoding.PEM))

    return


def create_ca():
    r = create_root_ca()
    create_inter(r)
    save_index({})

def getinterkeyandcert():
    with open(INTER_KEY, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(),
            password=b"Paraphraase",
            backend=default_backend()
        )
    with open(INTER_CERT, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return key, cert

def save_index(data):
    with open(INDEX_PATH, "w") as f:
        json.dump(data, f, indent=2)


def load_index():
    if not os.path.exists(INDEX_PATH):
        return {}
    with open(INDEX_PATH, "r") as f:
        return json.load(f)
