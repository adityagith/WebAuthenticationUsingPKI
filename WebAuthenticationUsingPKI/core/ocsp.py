from flask import Blueprint, render_template, request
from core.ca_utils import load_index

ocsp_routes = Blueprint("ocsp", __name__)

@ocsp_routes.route("/ocsp", methods=["GET", "POST"])

def ocsp_status():
    status = None
    if request.method == "POST":
        username = request.form["username"]
        index = load_index()
        if username not in index:
            status = "Unknown user"
        else:
            if index[username]["revoked"]:
                status = "Revoked"  
            else:
                status = "Valid"
    return render_template("ocsp_status.html", status=status)
