import os
import datetime 
from flask import Blueprint,request, render_template
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.backends import default_backend
from core.ca_utils import getinterkeyandcert,load_index

user_cert_routes = Blueprint("user_cert", __name__)

@user_cert_routes.route("/request-cert", methods=["GET", "POST"])

#User requesting a certicate(submits a csr)
def request_cert():

    if request.method == "POST":
        username = request.form["username"]
        country = request.form["country"]
        state = request.form["state"]
        locality = request.form["locality"]
        organization = request.form["organization"]
        # Key generated for the csr
        userkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            )
        
        #Creating a directory to save user pvt key and CSR
        user_dir = f"users/{username}"
        os.makedirs(user_dir, exist_ok=True)
        with open(f"{user_dir}/private_key.pem", "wb") as f:
            f.write(userkey.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
                ))

        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("pkisite1"),
                x509.DNSName("pkisite2"),
                x509.DNSName("pkisite3"),]),
                critical=False,
                ).sign(userkey, hashes.SHA256())
        with open(f"cert_requests/{username}_csr.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        return f"CSR for '{username}' submitted."

    return render_template("request_cert.html")
                    
                
@user_cert_routes.route("/login", methods=["GET","POST"])

@user_cert_routes.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("user_dashboard.html")

    username = request.form["username"]
    try:
        #Loading the user certificate according to username
        user_dir = f"users/{username}"
        with open(f"{user_dir}/cert.pem", "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        inter_cert = getinterkeyandcert()[1]

        # Verify the cert signature using the intermediate cert public key
        inter_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )

        #Verifying revocations status
        index = load_index()
        status = index.get(username, {}).get("revoked", True)
        user_entry = index.get(username)
        if user_entry==False:
            return "No User"
        elif(user_entry.get("revoked")==True):
            return "Certificate is revoked"
        return render_template("user_dashboard.html", username=username)
    except Exception as e:
        return f"Login failed: {e}"