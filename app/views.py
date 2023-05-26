# app/views.py
import io
import json
import pyotp
import qrcode

from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from fastapi_another_jwt_auth import AuthJWT
from nacl.encoding import Base64Encoder
from passlib.hash import bcrypt
from sqlalchemy.orm import Session

from .models import (
    get_db, Role, InstitutionalRole, User, Institutional, Project,
    ProjectType, RenewableEnergy, CarbonCredit,
    FeasibilityStudy, FinancingType, ProjectFinancing,
    UserSchema, InstitutionalSchema, LoginSchema,
    TwoFASchema, ProjectSchema, ProjectFinancingSchema
)

router = APIRouter()

############### GENERAL FUNCTIONS ###############
def generate_2fa():
    img_buf = io.BytesIO()
    uri = pyotp.totp.TOTP(app.config["TOTP_KEY"]).provisioning_uri(
        name="Admin",
        issuer_name="Carbon Sarhat"
    )
    img = qrcode.make(uri)
    img.save(img_buf)
    img_buf.seek(0)
    
    return Base64Encoder.encode(img_buf.getvalue()).decode("utf-8")

############### GETTER FUNCTIONS ###############
@router.get("/")
def home():
    return JSONResponse(content={"Message": "It works!"})

@router.get("/role")
def get_role():
    return JSONResponse(content={"Role": [role.value for role in Role]})

@router.get("/subrole")
def get_subrole():
    return JSONResponse(content={"Subrole": [role.value for role in InstitutionalRole]})

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
@router.post("/refresh", tags=["Authentication"])
async def refresh(
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_refresh_token_required()
    identity = Authorize.get_jwt_identity()
    access_token = Authorize.create_access_token(identity=identity)
    return {"access_token": access_token}

@router.post("/signup", tags=["Authentication"])
def signup(
    user_data: UserSchema, 
    institutional_data: InstitutionalSchema = None, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    try:
        email = user_data.email,
        user = db.query(User).filter_by(email=email).first()

        if user is not None:
            raise Exception("User Already Exists!")

        user = User(
            email=user_data.email,
            address=user_data.address,
            role=user_data.role
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        if institutional_data:
            institutional = Institutional(
                subrole=institutional_data.subrole,
                user_id=user.id,
                organization_name=institutional_data.organization_name,
                country=institutional_data.country,
                organization_address=institutional_data.organization_address,
                organization_registration_number=institutional_data.organization_registration_number,
                assets_under_management=institutional_data.assets_under_management,
                investment_ticket_preference=institutional_data.investment_ticket_preference,
                product_preference=institutional_data.product_preference,
                regions_of_interest=institutional_data.regions_of_interest,
                sector_of_interest=institutional_data.sector_of_interest
            )
            db.add(institutional)
            db.commit()
            db.refresh(institutional)

        access_token = Authorize.create_access_token(identity=email)
        refresh_token = Authorize.create_refresh_token(identity=email)
        result = {
            "status": True,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "message": "Signup successful"
        }

    except Exception as e:
        result = {"status": False, "message": str(e)}

    return result


@router.post("/login", tags=["Authentication"])
async def login(
    login_data: LoginSchema, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    try:
        email = login_data.email
        password = login_data.password
        user = db.query(User).filter_by(email=email).first()

        if not user or not bcrypt.verify(password, user.password):
            raise Exception("Invalid email or password!")

        access_token = Authorize.create_access_token(identity=email)
        refresh_token = Authorize.create_refresh_token(identity=email)
        result = {
            "status": True,
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    except Exception as e:
        result = {"status": False, "message": str(e)}

    return result

@router.post("/verify_2fa", tags=["Authentication"])
def verify_2fa(
    schema: TwoFASchema,
    Authorize: AuthJWT = Depends()
):
    try:
        code = schema.otp
        email = schema.email

        user = db.query(User).filter_by(email=email).first()
            
        if not user.admin:
            raise Exception("Not Admin")
        
        totp = pyotp.TOTP(app.config["TOTP_KEY"]).verify(code)
        if not totp:
            raise Exception("Invalid OTP")

        access_token = Authorize.create_access_token(identity=email)
        refresh_token = Authorize.create_refresh_token(identity=email)
        result = {
            "status": True,
            "access_token": access_token,
            "refresh_token": refresh_token
        }

    except Exception as e:
        result = {"status": False, "message": str(e)}
    
    return result

############### PROJECT FUNCTIONS ###############
@router.post("/projects", tags=["Project"])
async def create_project(
    project: ProjectSchema, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
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
            documents=project.documents
        )

        db.add(new_project)
        db.commit()

        result = {"status": True, "message": "Project created successfully"}

    except Exception as e:
        result = {"status": False, "message": str(e)}

    return result

@router.get("/project/{project_id}", tags=["Project"])
async def get_project(
    project_id: int, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    # Todo # Need to use JWT?
    try:
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
            "project_yield": project.project_yield
        }

        return project_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/projects/{project_id}", tags=["Project"])
async def update_project(
    project_id: int, 
    project: ProjectSchema, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        existing_project = db.query(Project).get(project_id)

        if not existing_project:
            raise HTTPException(status_code=404, detail="Project not found")

        existing_project.name = project.name or existing_project.name
        existing_project.website = project.website or existing_project.website
        existing_project.project_type = ProjectType.get(project.project_type, existing_project.project_type)
        existing_project.regulatory_approval = project.regulatory_approval or existing_project.regulatory_approval
        existing_project.feasibility_study = FeasibilityStudy.get(project.feasibility_study, existing_project.feasibility_study)
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

    except HTTPException as e:
        raise e

    except Exception as e:
        result = {"status": False, "message": str(e)}

    return result


@router.delete("/projects/{project_id}", tags=["Project"])
async def delete_project(
    project_id: int, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        existing_project = db.query(Project).get(project_id)

        if not existing_project:
            raise HTTPException(status_code=404, detail="Project not found")

        db.delete(existing_project)
        db.commit()

        result = {"status": True, "message": "Project deleted successfully"}

    except HTTPException as e:
        raise e

    except Exception as e:
        result = {"status": False, "message": str(e)}

    return result

@router.post("/project_financing", tags=["Project"])
async def create_project_financing(
    financing: ProjectFinancingSchema, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        project_financing = ProjectFinancing(
            project_id=financing.project_id,
            amount=financing.amount,
            financing_type=financing.financing_type
        )

        db.add(project_financing)
        db.commit()

        return {"status": True, "message": "Project financing created successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/project_financing/{financing_id}", tags=["Project"])
async def get_project_financing(
    financing_id: int, 
    db: Session = Depends(get_db), 
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required() # Todo # Maybe Remove?
    try:
        project_financing = db.query(ProjectFinancing).get(financing_id)

        if not project_financing:
            raise HTTPException(status_code=404, detail="Project financing not found")

        project_financing_data = {
            "id": project_financing.id,
            "project_id": project_financing.project_id,
            "amount": project_financing.amount,
            "financing_type": project_financing.financing_type.value,
        }

        return project_financing_data

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/projects/{project_id}/financing/{financing_id}", tags=["Project"])
async def update_project_financing(
    financing_id: int, 
    financing: ProjectFinancingSchema, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        project_financing = db.query(ProjectFinancing).get(financing_id)

        if not project_financing:
            raise HTTPException(status_code=404, detail="Project financing not found")

        project_financing.project_id = financing.project_id
        project_financing.amount = financing.amount
        project_financing.financing_type = financing.financing_type

        db.commit()

        return {"status": True, "message": "Project financing updated successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/projects/{project_id}/financing/{financing_id}", tags=["Project"])
async def delete_project_financing(
    project_id: int, 
    financing_id: int, 
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        financing = db.query(ProjectFinancing).get(financing_id)

        if not financing:
            raise HTTPException(status_code=404, detail="Project financing not found")

        db.delete(financing)
        db.commit()

        result = {"status": True, "message": "Project financing deleted successfully"}

    except HTTPException as e:
        raise e

    except Exception as e:
        result = {"status": False, "message": str(e)}

    return result

############### ADMIN FUNCTIONS ###############
@router.post("/whitelist/process/{user_id}", tags=["Admin"])
async def process_whitelist_user(
    user_id: int,
    action: str,
    db: Session = Depends(get_db),
    Authorize: AuthJWT = Depends()
):
    Authorize.jwt_required()
    try:
        email = Authorize.get_jwt_subject()
        current_user = db.query(User).filter(User.email == email).first()

        if not current_user:
            raise HTTPException(status_code=401, detail="Unauthorized")

        if current_user.role != Role.ADMIN:
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

    except HTTPException as e:
        raise e

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return result