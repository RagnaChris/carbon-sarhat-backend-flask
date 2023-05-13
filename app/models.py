from app import db, bcrypt
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql import func
from enum import Enum

class Role(Enum):
    ADMIN = "Admin"
    RETAIL = "Retail"
    CORPORATE = "Corporate"

class CorporateRole(Enum):
    GOVERNMENT = "Government"
    PROJECT_DEVELOPER = "Project Developer"
    FINANCE_INSTRUMENT = "Finance Instrument"
    ENTERPRISE = "Enterprise"

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(42))
    public_key = db.Column(db.String(64))
    email = db.Column(db.String(128), unique=True)
    _password = db.Column(db.String(128))
    role = db.Column(db.Enum(Role), nullable=False, default=Role.RETAIL)
    admin = db.Column(db.Boolean, default=False)

    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, text):
        self._password = bcrypt.generate_password_hash(text)

class Corporate(User):
    __tablename__ = "corporates"
    id = db.Column(db.Integer, primary_key=True, server_default=func.nextval("corporates_id_seq"))
    subrole = db.Column(db.Enum(CorporateRole), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    def __init__(self, address, public_key, email, password, subrole):
        super().__init__(
            address=address, 
            public_key=public_key, 
            email=email, 
            password=password, 
            role=Role.CORPORATE)
        self.subrole = subrole

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    corporate_id = db.Column(db.Integer, db.ForeignKey("corporates.id"))