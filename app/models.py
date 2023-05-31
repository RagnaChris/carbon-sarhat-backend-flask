# app/models.py
import os
from datetime import date
from dotenv import load_dotenv
from enum import Enum
from pydantic import BaseModel
from sqlalchemy import (
    Boolean, Column, create_engine,
    Date, Enum as EnumDB,
    Float, ForeignKey,
    Integer, String, Text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker, relationship
from typing import Optional

load_dotenv()
engine = create_engine(os.getenv("DATABASE_URI"))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

############### USER DATABASE ###############
class Role(Enum):
    ADMIN = "Admin"
    RETAIL = "Retail"
    INSTITUTIONAL = "Institutional"

class InstitutionalRole(Enum):
    ENERGY_PROJECT_DEVELOPER = "Energy Project Developer/ Sponsor"
    NATURE_BASED_PROJECT_DEVELOPER = "Nature-based Project Developer/ Sponsor"
    FINANCIAL_INSTITUTION = "Financial institution/ Credit Organization/ Licensed Investor"
    ENTERPRISE_AND_NGO = "Enterprise and NGO"
    GOVERNMENT = "Government Agency"
    OTHER = "Other"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(128), unique=True)
    _password = Column(String(128))
    address = Column(String(255))
    role = Column(EnumDB(Role), nullable=False, default=Role.RETAIL)
    admin = Column(Boolean, default=False)
    whitelisted = Column(Boolean, default=False)

    @property
    def password(self):
        return self._password

class Institutional(User):
    __tablename__ = "institutionals"
    institutional_id = Column(Integer, primary_key=True)
    subrole = Column(EnumDB(InstitutionalRole), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    organization_name = Column(String(255), nullable=False)
    country = Column(String(255), nullable=False)
    organization_address = Column(String(255), nullable=False)
    organization_registration_number = Column(String(255), nullable=False)
    assets_under_management = Column(String(255))
    investment_ticket_preference = Column(String(255))
    product_preference = Column(String(255))
    regions_of_interest = Column(String(255))
    sector_of_interest = Column(String(255))

############### PROJECT DATABASE ###############
class ProjectType(Enum):
    RENEWABLE_ENERGY = "Renewable Energy"
    CARBON_CREDIT = "Carbon Credit"

class RenewableEnergy(Enum):
    SOLAR_POWER = "Solar Power"
    WIND_POWER = "Wind Power"
    HYDRO_POWER = "Hydro Power"
    GEOTHERMAL = "Geothermal"
    BIOENERGY = "Bioenergy"
    WAVE = "Wave"
    HYDROGEN = "Hydrogen"

class CarbonCredit(Enum):
    NATURE_BASED_SOLUTION = "Nature-based Solution"
    CARBON_STORAGE = "Carbon Storage"
    WASTE_MANAGEMENT = "Waste Management"

class ProjectSubtype(Enum):
    RENEWABLE_ENERGY = RenewableEnergy
    CARBON_CREDIT = CarbonCredit

class FeasibilityStudy(Enum):
    DONE = "Done"
    NOT_YET = "Not yet"

class FinancingType(Enum):
    EQUITY = "Equity"
    DEBT = "Debt"

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    developer_id = Column(Integer, ForeignKey("institutionals.institutional_id"), nullable=False)
    name = Column(String(255), nullable=False)
    website = Column(String(255), nullable=False)
    project_type = Column(EnumDB(ProjectType), nullable=False)
    project_subtype = Column(EnumDB(ProjectSubtype), nullable=False)
    regulatory_approval = Column(Boolean, nullable=False)
    feasibility_study = Column(EnumDB(FeasibilityStudy), nullable=False)
    sustainable_goals = Column(String(255), nullable=False)
    third_party_verification = Column(String(255))
    size_capacity = Column(String(255), nullable=False)
    region = Column(String(255), nullable=False)
    project_bio = Column(Text, nullable=False)
    start_date = Column(Date, nullable=False)
    finish_date = Column(Date, nullable=False)
    financing_required = Column(Float, nullable=False)
    financing_type = Column(EnumDB(FinancingType), nullable=False)
    project_yield = Column(Float, nullable=False)

class ProjectFinancing(Base):
    __tablename__ = "project_financing"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    amount = Column(Float, nullable=False)
    financing_type = Column(EnumDB(FinancingType), nullable=False)


############### PYDANTIC MODELS ###############
class UserSchema(BaseModel):
    id: int
    email: str
    address: str
    role: Role

class InstitutionalSchema(UserSchema):
    subrole: InstitutionalRole
    organization_name: str
    country: str
    organization_address: str
    organization_registration_number: str
    assets_under_management: Optional[str]
    investment_ticket_preference: Optional[str]
    product_preference: Optional[str]
    regions_of_interest: Optional[str]
    sector_of_interest: Optional[str]

class LoginSchema(BaseModel):
    email: str
    password: str

class TwoFASchema(BaseModel):
    otp: int
    email: str

class ProjectSchema(BaseModel):
    id: int
    name: str
    website: str
    project_type: ProjectType
    project_subtype: str
    regulatory_approval: bool
    feasibility_study: FeasibilityStudy
    sustainable_goals: str
    third_party_verification: str
    size_capacity: str
    region: str
    project_bio: str
    start_date: date
    finish_date: date
    financing_required: float
    financing_type: FinancingType
    project_yield: float

    class Config:
        orm_mode = True

class ProjectFinancingSchema(BaseModel):
    id: int
    project_id: int
    amount: float
    financing_type: FinancingType

    class Config:
        orm_mode = True