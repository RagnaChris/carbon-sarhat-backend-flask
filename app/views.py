# app/views.py
import io
import os

import pyotp
import qrcode
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, Response
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from fastapi_another_jwt_auth import AuthJWT
from nacl.encoding import Base64Encoder
from passlib.hash import bcrypt
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .models import (
    CarbonCredit,
    FeasibilityStudy,
    FinancingType,
    Institution,
    InstitutionRole,
    InstitutionSchema,
    LoginSchema,
    Project,
    ProjectFinancing,
    ProjectFinancingSchema,
    ProjectSchema,
    ProjectType,
    RenewableEnergy,
    Role,
    TwoFASchema,
    User,
    UserSchema,
    WhitelistAction,
    get_db,
)

load_dotenv()
router = APIRouter()


############### AUTHJWT CONFIG ###############
class Settings(BaseModel):
    authjwt_secret_key: str = os.getenv("JWT_SECRET_KEY")
    authjwt_token_location: set = {"headers"}


@AuthJWT.load_config
def get_config():
    return Settings()


############### GENERAL FUNCTIONS ###############
def generate_2fa():
    img_buf = io.BytesIO()
    uri = pyotp.totp.TOTP(os.getenv("TOTP_KEY")).provisioning_uri(name="Admin", issuer_name="Carbon Sarhat")
    img = qrcode.make(uri)
    img.save(img_buf)
    img_buf.seek(0)

    return Base64Encoder.encode(img_buf.getvalue()).decode("utf-8")


def only_developer(Authorize, db):
    subject = Authorize.get_jwt_subject()
    user = db.query(User).filter_by(email=subject).first()
    if user.role != Role.INSTITUTION.value:
        raise Exception("Not institution user.")

    if (
        user.subrole != InstitutionRole.ENERGY_PROJECT_DEVELOPER.value
        or user.subrole != InstitutionRole.NATURE_BASED_PROJECT_DEVELOPER.value
    ):
        raise Exception("Not Developer.")

    return user


############### GETTER FUNCTIONS ###############
@router.get("/")
def home():
    return JSONResponse(content={"Message": "It works!"})


@router.get("/role")
def get_role():
    return JSONResponse(content={"Role": [role.value for role in Role]})


@router.get("/subrole")
def get_subrole():
    return JSONResponse(content={"Subrole": [role.value for role in InstitutionRole]})


@router.get("/project_type")
def get_project_type():
    return JSONResponse(content={"ProjectType": [ptype.value for ptype in ProjectType]})


@router.get("/renewable_energy")
def get_renewable_energy():
    return JSONResponse(content={"RenewableEnergy": [energy.value for energy in RenewableEnergy]})


@router.get("/carbon_credit")
def get_carbon_credit():
    return JSONResponse(content={"CarbonCredit": [credit.value for credit in CarbonCredit]})


@router.get("/feasibility_study")
def get_feasibility_study():
    return JSONResponse(content={"FeasibilityStudy": [study.value for study in FeasibilityStudy]})


@router.get("/financing_type")
def get_financing_type():
    return JSONResponse(content={"FinancingType": [ftype.value for ftype in FinancingType]})


############### AUTHENTICATION FUNCTIONS ###############
@router.post(
    "/refresh",
    tags=["Authentication"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {"application/json": {"example": {"status": True, "access_token": "JWT_ACCESS_TOKEN"}}},
        },
    },
)
async def refresh(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    subject = Authorize.get_jwt_subject()
    claims = Authorize.get_raw_jwt()["role"]
    access_token = Authorize.create_access_token(subject=subject, user_claims={"role": claims})
    return {"status": True, "access_token": access_token}


@router.post(
    "/signup",
    tags=["Authentication"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "access_token": "JWT_ACCESS_TOKEN",
                        "refresh_token": "JWT_REFRESH_TOKEN",
                        "message": "Signup success",
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
def signup(
    response: Response,
    user_data: UserSchema = None,
    institution_data: InstitutionSchema = None,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    try:
        email = ""
        if user_data:
            email = str(user_data.email)
        elif institution_data:
            email = str(institution_data.email)

        user = db.query(User).filter_by(email=email).first()

        if user is not None:
            raise Exception("User Already Exists!")

        role = ""
        if user_data:
            role = "User"
            user = User(
                email=email,
                password=bcrypt.hash(user_data.password),
                firstName=user_data.firstName,
                lastName=user_data.lastName,
                accreditedInvestor=user_data.accreditedInvestor,
                phoneNumber=user_data.phoneNumber,
                country=user_data.country,
                address=user_data.address,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        elif institution_data:
            role = "Institution"
            institution = Institution(
                email=institution_data.email,
                password=bcrypt.hash(institution_data.password),
                role=Role.INSTITUTION.value,
                subrole=institution_data.subrole,
                organization_name=institution_data.organization_name,
                country=institution_data.country,
                organization_address=institution_data.organization_address,
                organization_registration_number=institution_data.organization_registration_number,
                assets_under_management=institution_data.assets_under_management,
                investment_ticket_preference=institution_data.investment_ticket_preference,
                product_preference=institution_data.product_preference,
                regions_of_interest=institution_data.regions_of_interest,
                sector_of_interest=institution_data.sector_of_interest,
            )
            db.add(institution)
            db.commit()
            db.refresh(institution)
        else:
            raise Exception("Not known role.")

        claims = {"role": role}
        access_token = Authorize.create_access_token(subject=email, user_claims=claims)
        refresh_token = Authorize.create_refresh_token(subject=email)

        result = {
            "status": True,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "message": "Signup success",
        }

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.post(
    "/login",
    tags=["Authentication"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "access_token": "JWT_ACCESS_TOKEN",
                        "refresh_token": "JWT_REFRESH_TOKEN",
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def login(
    login_data: LoginSchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()
):
    try:
        email = str(login_data.email)
        password = login_data.password
        user = db.query(User).filter_by(email=email).first()

        if not user or not bcrypt.verify(password, user.password):
            raise Exception("Invalid email or password!")

        claims = {"role": user.role}
        access_token = Authorize.create_access_token(subject=email, user_claims=claims)
        refresh_token = Authorize.create_refresh_token(subject=email)

        response.status_code = 200
        return {"status": True, "access_token": access_token, "refresh_token": refresh_token}

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.post(
    "/verify_2fa",
    tags=["Authentication"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "access_token": "JWT_ACCESS_TOKEN",
                        "refresh_token": "JWT_REFRESH_TOKEN",
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
def verify_2fa(schema: TwoFASchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    try:
        code = schema.otp
        email = str(schema.email)

        user = db.query(User).filter_by(email=email).first()

        if not user.admin:
            raise Exception("Not Admin")

        totp = pyotp.TOTP(os.getenv["TOTP_KEY"]).verify(code)
        if not totp:
            raise Exception("Invalid OTP")

        access_token = Authorize.create_access_token(subject=email)
        refresh_token = Authorize.create_refresh_token(subject=email)

        response.status_code = 200
        return {"status": True, "access_token": access_token, "refresh_token": refresh_token}

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


############### PROJECT FUNCTIONS ###############
@router.post(
    "/project",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {"status": True, "project_id": 1, "message": "Project created successfully"}
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def create_project(
    project: ProjectSchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        only_developer(Authorize, db)

        subtype = project.subtype
        if subtype in [energy.value for energy in RenewableEnergy]:
            project_subtype = RenewableEnergy[subtype]
        elif subtype in [credit.value for credit in CarbonCredit]:
            project_subtype = CarbonCredit[subtype]
        else:
            raise Exception("Unknown Project Subtype")

        new_project = Project(
            name=project.name,
            website=project.website,
            project_type=ProjectType[project.project_type],
            project_subtype=project_subtype,
            regulatory_approval=project.regulatory_approval,
            feasibility_study=FeasibilityStudy[project.feasibility_study],
            sustainable_goals=project.sustainable_goals,
            size_capacity=project.size_capacity,
            region=project.region,
            project_bio=project.project_bio,
            start_date=project.start_date,
            finish_date=project.finish_date,
            financing_required=project.financing_required,
            financing_type=FinancingType[project.financing_type],
            project_yield=project.project_yield,
            documents=project.documents,
        )

        db.add(new_project)
        db.commit()

        response.status_code = 200
        return {"status": True, "project_id": new_project.id, "message": "Project created successfully"}

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.get(
    "/project/{project_id}",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "project": {
                            "id": 1234,
                            "name": "Project Name",
                            "website": "https://example.com",
                            "project_type": "Carbon Credit",
                            "project_subtype": "Carbon Storage",
                            "regulatory_approval": True,
                            "feasibility_study": "Done",
                            "sustainable_goals": "Some Sustainable Goals",
                            "third_party_verification": True,
                            "size_capacity": "Some Size/Capacity",
                            "region": "Some Region",
                            "project_bio": "Project Bio",
                            "start_date": "2023-07-01T00:00:00Z",
                            "finish_date": "2023-07-31T23:59:59Z",
                            "financing_required": 1000000,
                            "financing_type": "Some Financing Type",
                            "project_yield": 100,
                        },
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def get_project(
    project_id: int, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        subject = Authorize.get_jwt_subject()
        user = db.query(User).filter_by(email=subject).first()
        if user.role == Role.USER:
            raise Exception("User not allowed.")

        project = db.query(Project).get(project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        project_data = {
            "id": project.id,
            "name": project.name,
            "website": project.website,
            "project_type": project.project_type.value,
            "project_subtype": project.project_subtype.value,
            "regulatory_approval": project.regulatory_approval,
            "feasibility_study": project.feasibility_study.value,
            "sustainable_goals": project.sustainable_goals,
            "third_party_verification": project.third_party_verification,
            "size_capacity": project.size_capacity,
            "region": project.region,
            "project_bio": project.project_bio,
            "start_date": project.start_date.isoformat(),
            "finish_date": project.finish_date.isoformat(),
            "financing_required": project.financing_required,
            "financing_type": project.financing_type.value,
            "project_yield": project.project_yield,
        }

        response.status_code = 200
        return {"status": True, "project": project_data}

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.get(
    "/projects/",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "projects": [
                            {
                                "id": 1234,
                                "name": "Project Name",
                                "website": "https://example.com",
                                "project_type": "Carbon Credit",
                                "project_subtype": "Carbon Storage",
                                "regulatory_approval": True,
                                "feasibility_study": "Done",
                                "sustainable_goals": "Some Sustainable Goals",
                                "third_party_verification": True,
                                "size_capacity": "Some Size/Capacity",
                                "region": "Some Region",
                                "project_bio": "Project Bio",
                                "start_date": "2023-07-01T00:00:00Z",
                                "finish_date": "2023-07-31T23:59:59Z",
                                "financing_required": 1000000,
                                "financing_type": "Some Financing Type",
                                "project_yield": 100,
                            }
                        ],
                        "next_cursor": "None",
                    }
                }
            },
        },
    },
)
def get_projects(response: Response, page_size: int = 25, cursor: int = None, db: Session = Depends(get_db)):
    projects_query = db.query(Project).order_by(desc(Project.id))

    if cursor:
        projects_query = projects_query.filter(Project.id < cursor)

    projects = projects_query.limit(page_size).all()
    new_cursor = projects[-1].id if projects else None

    response.status_code = 200
    return {"status": True, "projects": projects, "next_cursor": new_cursor}


@router.put(
    "/project/{project_id}",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {"application/json": {"example": {"status": True, "message": "Project updated successfully"}}},
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def update_project(
    project_id: int,
    project: ProjectSchema,
    response: Response,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    Authorize.jwt_required()
    try:
        user = only_developer(Authorize, db)
        existing_project = db.query(Project).get(project_id)

        if not existing_project:
            raise HTTPException(status_code=404, detail="Project not found")

        if user.institution_id != existing_project.developer_id:
            raise Exception("Not the project developer.")

        existing_project.name = project.name or existing_project.name
        existing_project.website = project.website or existing_project.website
        existing_project.project_type = ProjectType.get(project.project_type, existing_project.project_type)
        existing_project.regulatory_approval = project.regulatory_approval or existing_project.regulatory_approval
        existing_project.feasibility_study = FeasibilityStudy.get(
            project.feasibility_study, existing_project.feasibility_study
        )
        existing_project.sustainable_goals = project.sustainable_goals or existing_project.sustainable_goals
        existing_project.size_capacity = project.size_capacity or existing_project.size_capacity
        existing_project.region = project.region or existing_project.region
        existing_project.project_bio = project.project_bio or existing_project.project_bio
        existing_project.start_date = project.start_date or existing_project.start_date
        existing_project.finish_date = project.finish_date or existing_project.finish_date
        existing_project.financing_required = project.financing_required or existing_project.financing_required
        existing_project.financing_type = FinancingType.get(project.financing_type, existing_project.financing_type)
        existing_project.project_yield = project.project_yield or existing_project.project_yield
        existing_project.documents = project.documents or existing_project.documents

        db.commit()

        result = {"status": True, "message": "Project updated successfully"}

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.delete(
    "/project/{project_id}",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {"application/json": {"example": {"status": True, "message": "Project deleted successfully"}}},
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def delete_project(
    project_id: int, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        user = only_developer(Authorize, db)
        existing_project = db.query(Project).get(project_id)

        if not existing_project:
            raise HTTPException(status_code=404, detail="Project not found")

        if user.institution_id != existing_project.developer_id:
            raise Exception("Not the project developer.")

        db.delete(existing_project)
        db.commit()

        result = {"status": True, "message": "Project deleted successfully"}

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.post(
    "/project_financing",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "project_financing_id": 1,
                        "message": "Project financing created successfully",
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def create_project_financing(
    financing: ProjectFinancingSchema, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        only_developer(Authorize, db)

        project_financing = ProjectFinancing(
            project_id=financing.project_id, amount=financing.amount, financing_type=financing.financing_type
        )

        db.add(project_financing)
        db.commit()

        response.status_code = 200
        return {
            "status": True,
            "project_financing_id": project_financing.id,
            "message": "Project financing created successfully",
        }

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.get(
    "/project_financing/{financing_id}",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "project": {"id": 1234, "project_id": 5678, "amount": 100000, "financing_type": "Equity"},
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def get_project_financing(
    financing_id: int, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        subject = Authorize.get_jwt_subject()
        user = db.query(User).filter_by(email=subject).first()
        if user.role == Role.USER:
            raise Exception("User not allowed.")

        project_financing = db.query(ProjectFinancing).get(financing_id)

        if not project_financing:
            raise HTTPException(status_code=404, detail="Project financing not found")

        project_financing_data = {
            "id": project_financing.id,
            "project_id": project_financing.project_id,
            "amount": project_financing.amount,
            "financing_type": project_financing.financing_type.value,
        }

        response.status_code = 200
        return {"status": True, "project": project_financing_data}

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.put(
    "/projects/{project_id}/financing/{financing_id}",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {"example": {"status": True, "message": "Project financing updated successfully"}}
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def update_project_financing(
    financing_id: int,
    financing: ProjectFinancingSchema,
    response: Response,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    Authorize.jwt_required()
    try:
        user = only_developer(Authorize, db)
        project_financing = db.query(ProjectFinancing).get(financing_id)

        if not project_financing:
            raise HTTPException(status_code=404, detail="Project financing not found")

        if user.institution_id != project_financing.developer_id:
            raise Exception("Not the project developer.")

        project_financing.project_id = financing.project_id
        project_financing.amount = financing.amount
        project_financing.financing_type = financing.financing_type

        db.commit()

        response.status_code = 200
        return {"status": True, "message": "Project financing updated successfully"}

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.delete(
    "/projects/{project_id}/financing/{financing_id}",
    tags=["Project"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {"example": {"status": True, "message": "Project financing deleted successfully"}}
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def delete_project_financing(
    project_id: int,
    financing_id: int,
    response: Response,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    Authorize.jwt_required()
    try:
        user = only_developer(Authorize, db)
        financing = db.query(ProjectFinancing).get(financing_id)

        if not financing:
            raise HTTPException(status_code=404, detail="Project financing not found")

        if user.institution_id != financing.developer_id:
            raise Exception("Not the project developer.")

        db.delete(financing)
        db.commit()

        result = {"status": True, "message": "Project financing deleted successfully"}

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


############### ADMIN FUNCTIONS ###############
@router.get(
    "/users",
    tags=["Admin"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "users": [
                            {
                                "id": 1,
                                "email": "user1@example.com",
                                "password": "hashed_password",
                                "firstName": "John",
                                "lastName": "Doe",
                                "accreditedInvestor": False,
                                "phoneNumber": "123456789",
                                "country": "USA",
                                "address": "123 Main St",
                                "role": "user",
                                "admin": False,
                                "whitelisted": False,
                                "verified": True,
                            },
                        ],
                        "next_cursor": "None",
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def get_users(
    user_id: int,
    response: Response,
    page_size: int = 25,
    cursor: int = None,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    Authorize.jwt_required()
    try:
        email = Authorize.get_jwt_subject()
        current_user = db.query(User).filter(User.email == email).first()

        if not current_user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not current_user.admin:
            raise HTTPException(status_code=403, detail="Only admin can perform this action")

        users_query = db.query(User).filter(User.verified == True).order_by(desc(User.id))

        if cursor:
            users_query = users_query.filter(User.id < cursor)

        users = users_query.limit(page_size).all()
        new_cursor = users[-1].id if users else None

        result = {"users": users, "next_cursor": new_cursor}

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.get(
    "/unverified-users",
    tags=["Admin"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {
                    "example": {
                        "status": True,
                        "users": [
                            {
                                "id": 1,
                                "email": "user1@example.com",
                                "password": "hashed_password",
                                "firstName": "John",
                                "lastName": "Doe",
                                "accreditedInvestor": False,
                                "phoneNumber": "123456789",
                                "country": "USA",
                                "address": "123 Main St",
                                "role": "user",
                                "admin": False,
                                "whitelisted": False,
                                "verified": False,
                            },
                        ],
                        "next_cursor": "None",
                    }
                }
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def get_unverified_users(
    user_id: int,
    response: Response,
    page_size: int = 25,
    cursor: int = None,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    Authorize.jwt_required()
    try:
        email = Authorize.get_jwt_subject()
        current_user = db.query(User).filter(User.email == email).first()

        if not current_user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not current_user.admin:
            raise HTTPException(status_code=403, detail="Only admin can perform this action")

        users_query = db.query(User).filter(User.verified == False).order_by(desc(User.id))

        if cursor:
            users_query = users_query.filter(User.id < cursor)

        users = users_query.limit(page_size).all()
        new_cursor = users[-1].id if users else None

        result = {"status": True, "users": users, "next_cursor": new_cursor}

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.post(
    "/verify/process/{user_id}",
    tags=["Admin"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {"application/json": {"example": {"status": True, "message": "User verified successfully"}}},
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def verify_user(user_id: int, response: Response, db: Session = Depends(get_db), Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    try:
        email = Authorize.get_jwt_subject()
        current_user = db.query(User).filter(User.email == email).first()

        if not current_user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not current_user.admin:
            raise HTTPException(status_code=403, detail="Only admin can perform this action")

        user = db.query(User).get(user_id)

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.verified = True
        db.commit()
        result = {"status": True, "message": "User verified successfully"}

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}


@router.post(
    "/whitelist/process/{user_id}",
    tags=["Admin"],
    responses={
        200: {
            "description": "Successful Response",
            "content": {
                "application/json": {"example": {"status": True, "message": "User added to the whitelist successfully"}}
            },
        },
        500: {
            "description": "Error",
            "content": {"application/json": {"example": {"status": False, "message": "Error"}}},
        },
    },
)
async def process_whitelist_user(
    user_id: int,
    action: WhitelistAction,
    response: Response,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends(),
):
    Authorize.jwt_required()
    try:
        email = Authorize.get_jwt_subject()
        current_user = db.query(User).filter(User.email == email).first()

        if not current_user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        if not current_user.admin:
            raise HTTPException(status_code=403, detail="Only admin can perform this action")

        user = db.query(User).get(user_id)

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if action == "add":
            user.whitelisted = True
            db.commit()
            result = {"status": True, "message": "User added to the whitelist successfully"}
        elif action == "remove":
            user.whitelisted = False
            db.commit()
            result = {"status": True, "message": "User removed from the whitelist successfully"}
        else:
            raise HTTPException(status_code=400, detail="Invalid action")

        response.status_code = 200
        return result

    except Exception as e:
        response.status_code = 500
        return {"status": False, "message": str(e)}
