# app/views.py
import io
import json
import jwt
import pyotp
import qrcode
import secrets
import string
import time

from flask import request, jsonify
from functools import wraps
from nacl.encoding import Base64Encoder, HexEncoder
from nacl.signing import VerifyKey
from app import db, app, bcrypt
from .models import  Role, CorporateRole, User, Corporate, Project

############### GENERAL FUNCTIONS ###############
code_size = 20

def generate_2fa():
    img_buf = io.BytesIO()
    uri = pyotp.totp.TOTP(app.config["TOTP_KEY"]).provisioning_uri(
        name='Admin',
        issuer_name='Carbon Sarhat'
    )
    
    img = qrcode.make(uri)
    img.save(img_buf)
    img_buf.seek(0)
    
    return Base64Encoder.encode(img_buf.getvalue()).decode("utf-8")

def generate_jwt(hour):
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    code = "".join(secrets.choice(characters) for i in range(code_size))
    payload = {
        "code": code,
        "expiredAt": round(time.time()) + 60 * 60 * hour
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    return token

def check_jwt_expire(token_data):
    if token_data["expiredAt"] < round(time.time()):
        result = {
            "status": False,
            "message": "Request connect expired."
        }

        raise Exception("Request expired.")

def verify_signature(token, public_key, signature):
    token_data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    check_jwt_expire(token_data)

    msg = Base64Encoder.encode(bytes(token_data["code"], "utf-8"))
    pub_key = VerifyKey(public_key, encoder=HexEncoder)
    signature = HexEncoder.decode(signature)
    verified = pub_key.verify(msg, signature)

    if not verified:
        result = {
            "status": False,
            "message": "Not the same address."
        }

        raise Exception("Different address")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        
        if not token:
            return jsonify({"status": False, "message": "Token is missing."})
        
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"])
            check_expired(data)
            user = User.query\
                .filter((User.address == data["address"]) | (User.email == data["email"]))\
                .first()
        except:
            return jsonify({"status": False, "message": "Token is invalid."})
        
        return f(user, *args, **kwargs)
    return decorated


############### ROUTE FUNCTIONS ###############
@app.route("/")
def home():
    return jsonify({"Message": "It works!"})

@app.route("/subrole", methods=["GET"])
def get_subrole():
    return jsonify({"Subrole": [role.value for role in CorporateRole]})

@app.route("/request-token", methods=["GET"])
def request_token():
    token = generate_jwt(1)
    result = {
            "status": True,
            "token": token
        }
    
    return jsonify(result)

@app.route("/signup", methods=["POST"])
def signup():
    try:
        data = json.loads(request.data)
        role = data["role"]
        address = data["address"]
        public_key = data["public_key"]
        email = data["email"]

        user = User.query\
                .filter((User.email == email) | (User.address == address))\
                .first()
                
        if user is not None:
            raise Exception("User Already Exist!")
        
        if role == Role.RETAIL.value:
            token = data["token"]
            signature = data["signature"]
            verify_signature(token, public_key, signature)
            retail = User(address=address, public_key=public_key, email=email)
            db.session.add(retail)
        elif role == Role.CORPORATE.value:
            subrole = data["subrole"]
            if subrole not in [subroles.value for subroles in CorporateRole]:
                raise Exception("Subrole Does Not Exist!")
            password = data["password"]
            corporate = Corporate(
                email=email, 
                address=address, 
                public_key=public_key, 
                password=password, 
                subrole=subrole
            )
            
            db.session.add(corporate)
        else:
            raise Exception("Role Does Not Exist!")
        
        db.session.commit()

        token = generate_jwt(5)
        result = {
            "status": True,
            "token": token
        }
        
    except Exception as e:
        if e.args:
            msg = e.args[0]
        else:
            msg = "Unknown error."
        
        result = {
            "status": False,
            "message": msg
        }
    
    return jsonify(result)

@app.route("/login", methods=["POST"])
def login():
    try:
        data = json.loads(request.data)
        address = data["address"]
        pub_key = data["public_key"]

        user = User.query\
                .filter((User.address == data["address"]) | (User.email == data["email"]))\
                .first()
        
        if not user:
            raise Exception("Invalid email, address, and/or password.")

        if user.role == Role.RETAIL:
            token = data["token"]
            signature = data["signature"]
            verify_signature(token, public_key, signature)
        else:
            if not bcrypt.check_password_hash(user.password, data["password"]):
                raise Exception("Invalid email, address, and/or password.")

        if user.admin:
            response = generate_2fa()
            result = {
                "status": True,
                "msg": "QRCode send",
                "response": response
            }

        else:
            token = generate_jwt(5)
            result = {
                "status": True,
                "token": token
            }
    
    except Exception as e:
        if e.args:
            msg = e.args[0]
        else:
            msg = "Unknown error."
        
        result = {
            "status": False,
            "message": msg
        }
    
    return jsonify(result)

@app.route("/verify_2fa", methods=["POST"])
def verify_2fa():
    try:
        data = json.loads(request.data)
        code = data["code"]
        totp = pyotp.TOTP(app.config["TOTP_KEY"]).verify(code)
        token = generate_jwt(5)
        result = {
            "status": True,
            "token": token
        }

    except Exception as e:
        if e.args:
            msg = e.args[0]
        else:
            msg = "Unknown error."
        
        result = {
            "status": False,
            "message": msg
        }
    
    return jsonify(result)

############### ADMIN FUNCTIONS ###############
# TODO
# Process Whitelist (Add, Remove)
# Role Change for other users
# Check credibility of email (Just allow for now)

############### WEB3 FUNCTIONS ###############