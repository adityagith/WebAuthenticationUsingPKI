import os
import datetime
from flask import Blueprint, render_template, redirect, url_for,request
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.backends import default_backend
from core.ca_utils import getinterkeyandcert, save_index, load_index

admin_routes = Blueprint("admin", __name__)




#PKI Admin Authentication using his certificate
@admin_routes.route("/pkilogin", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("adminview.html")
    username = request.form["username"]
    cert_file = request.files["cert"]
    try:
        #Loading the pki admin certificate 
        cert_data = cert_file.read()
        pkiadmincert = x509.load_pem_x509_certificate(cert_data)
        inter_cert = getinterkeyandcert()[1]
        # Verify the cert signature using the intermediate cert public key
        inter_cert.public_key().verify(
            pkiadmincert.signature,
            pkiadmincert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            pkiadmincert.signature_hash_algorithm)

        #Verify if its pkiamdin only
        subject = pkiadmincert.subject
        common_name = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if common_name != "PKI Admin":
            return "Access denied: Certificate is not for 'pkiadmin'."

        #Verifying revocations status
        index = load_index()
        status = index.get(username, {}).get("revoked", True)
        user_entry = index.get(username)

        if user_entry==False:
            return "No User"
        elif(user_entry.get("revoked")==True):
            return "Certificate is revoked"
        return render_template("adminview.html")
    except Exception as e:
        return f"Login failed: {e}"


@admin_routes.route("/admin")
def admin_panel():
    pending = [f.replace("_csr.pem", "") for f in os.listdir("cert_requests")]
    issued = load_index()
    return render_template("admin.html", pending=pending, issued=issued)


@admin_routes.route("/admin/approve/<username>")
def approve_cert(username):

    try:
        #Get ca key to sign the user csr
        inter_key,inter_cert = getinterkeyandcert()
        with open(f"cert_requests/{username}_csr.pem", "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(inter_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(inter_key, hashes.SHA256())
        )
        #issue certificate to users
        with open(f"users/{username}/cert.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        os.remove(f"cert_requests/{username}_csr.pem")
        #update certificate database
        index = load_index()
        index[username] = {"serial": cert.serial_number, "revoked": False}
        save_index(index)

    except Exception as e:
        return str(e)
    return redirect(url_for("admin.admin_panel"))

#Rejecting the request
@admin_routes.route("/admin/reject/<username>")
def reject_cert(username):
    index = load_index()
    if username in index:
        index[username]["revoked"] = True
        save_index(index)
    return redirect(url_for("admin.admin_panel"))


#Revocation for users
@admin_routes.route("/admin/revoke/<username>")
def revoke_cert(username):
    index = load_index()
    if username in index:
        index[username]["revoked"] = True
        save_index(index)
    return redirect(url_for("admin.admin_panel"))
