import os
import datetime
from flask import Blueprint, render_template, redirect, url_for
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from core.ca_utils import getinterkeyandcert, save_index, load_index

admin_routes = Blueprint("admin", __name__)

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

#Revocation for users
@admin_routes.route("/admin/revoke/<username>")
def revoke_cert(username):
    index = load_index()
    if username in index:
        index[username]["revoked"] = True
        save_index(index)
    return redirect(url_for("admin.admin_panel"))
