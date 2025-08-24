from flask import Flask, render_template
from core.ca_utils import create_ca
from core.user_cert import user_cert_routes
from core.admin import admin_routes
from core.ocsp import ocsp_routes

app = Flask(__name__)

app.register_blueprint(user_cert_routes)
app.register_blueprint(admin_routes)
app.register_blueprint(ocsp_routes)

@app.route("/")

def home():
    return render_template("index.html")

if __name__=="__main__":
    create_ca()
    app.run(debug=True)