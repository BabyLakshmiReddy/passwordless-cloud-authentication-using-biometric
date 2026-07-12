import json
import os
import uuid
import datetime
import time

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    send_from_directory
)

from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization

from core.crypto_engine import (
    derive_keys_fuzzy,
    reproduce_key_fuzzy,
    sign_challenge,
    verify_challenge,
    generate_visual_id
)

app = Flask(__name__)
app.secret_key = "secure_ecc_vault_key_2026"

# ---------------- Configuration ---------------- #

app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME="penkijyothi2004@gmail.com",
    MAIL_PASSWORD="uaactsxphtmlkaxt"
)

mail = Mail(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(BASE_DIR, "database.json")
LOG_PATH = os.path.join(BASE_DIR, "admin_logs.json")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "vault_storage")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- Helpers ---------------- #

def io_db(data=None):
    if data is None:
        if os.path.exists(DB_PATH):
            with open(DB_PATH, "r") as f:
                return json.load(f)
        return {}

    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=4)


def log(user, action, status, proof="N/A"):
    logs = []

    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, "r") as f:
            logs = json.load(f)

    logs.append({
        "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "action": action,
        "status": status,
        "proof": proof
    })

    with open(LOG_PATH, "w") as f:
        json.dump(logs, f, indent=4)


def notify(subject, receiver, name, status):
    msg = Message(
        subject,
        sender=app.config["MAIL_USERNAME"],
        recipients=[receiver]
    )

    msg.body = f"""
Hello {name},

Event : {status}
Time  : {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Thank you.
"""

    try:
        mail.send(msg)
    except Exception:
        log("SYSTEM", "Mail", "Failed")


# ---------------- Routes ---------------- #

@app.route("/")
def index():
    return render_template("index.html")
@app.route("/register_page")
def register_page():
    return render_template("register.html")


@app.route("/login_page")
def login_page():
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    db = io_db()

    if data["username"] in db:
        return jsonify({"status": "Exists"}), 400

    try:
        private_key, public_key, helper_data = derive_keys_fuzzy(
            data["biometric_data"]
        )

        db[data["username"]] = {
            **data,
            "public_key": public_key,
            "helper_data": helper_data.hex(),
            "vault": [],
            "role": "user"
        }

        io_db(db)

        log(data["username"], "Registration", "Success")

        notify(
            "Welcome",
            data["email"],
            data["full_name"],
            "Registered Successfully"
        )

        return jsonify({
            "status": "Success",
            "visual_signature": generate_visual_id(
                private_key,
                data["username"]
            )
        })

    except Exception as e:
        return jsonify({
            "status": "Error",
            "reason": str(e)
        }), 400

@app.route("/get_user_details", methods=["POST"])
def get_user_details():

    data = request.json
    db = io_db()

    user = db.get(data["username"])

    if not user:
        return jsonify({
            "status": "failed",
            "reason": "User not found"
        }), 404

    if user["public_key"] != data["public_key"]:
        return jsonify({
            "status": "failed",
            "reason": "Public key mismatch"
        }), 401

    return jsonify({
        "status": "success",
        "name": user["full_name"],
        "cloud_id": user["username"]
    })

@app.route("/verify_match", methods=["POST"])
def verify_match():
    data = request.json
    db = io_db()

    user = db.get(data["username"])

    if not user:
        return jsonify({"status": "User Not Found"}), 404

    try:
        private_key = reproduce_key_fuzzy(
            data["biometric_data"],
            bytes.fromhex(user["helper_data"]),
            5000
        )

        session["temp_priv"] = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).hex()

        session["audit_user"] = data["username"]

        return jsonify({
            "status": "Matched",
            "redirect": "/audit_screen"
        })

    except Exception:
        log(data["username"], "Login", "Failed")
        return jsonify({"status": "Error"}), 401


@app.route("/verify_ecdsa", methods=["POST"])
def verify_ecdsa():
    user_id = session.get("audit_user")
    private_hex = session.get("temp_priv")

    db = io_db()

    if not user_id or not private_hex:
        return jsonify({"status": "Session Expired"}), 401

    try:
        private_key = serialization.load_pem_private_key(
            bytes.fromhex(private_hex),
            password=None
        )

        challenge = str(uuid.uuid4())

        signature = sign_challenge(private_key, challenge)

        if verify_challenge(
            db[user_id]["public_key"],
            challenge,
            signature
        ):
            session["user"] = user_id
            session.pop("temp_priv", None)

            log(user_id, "ECDSA Login", "Success")

            notify(
                "Login Alert",
                db[user_id]["email"],
                user_id,
                "Login Successful"
            )

            return jsonify({"status": "Verified"})

        return jsonify({"status": "Verification Failed"}), 401

    except Exception as e:
        return jsonify({
            "status": "Error",
            "reason": str(e)
        }), 401


@app.route("/upload_file", methods=["POST"])
def upload_file():
    if "user" not in session:
        return "Unauthorized", 401

    file = request.files["file"]

    filename = secure_filename(file.filename)

    file.save(os.path.join(UPLOAD_FOLDER, filename))

    db = io_db()

    db[session["user"]]["vault"].append({
        "type": "File",
        "name": filename,
        "uploaded_at": str(datetime.datetime.now())
    })

    io_db(db)

    return jsonify({"status": "Success"})


@app.route("/get_vault")
def get_vault():
    if "user" not in session:
        return jsonify([])

    db = io_db()

    return jsonify(
        db.get(session["user"], {}).get("vault", [])
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, port=5001)
