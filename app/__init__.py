# app/__init__.py
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware

from .models import Base, engine
from .views import router

# Create FastAPI app instance
app = FastAPI()

# Set up CORS
origins = ["*"]  # Update with your frontend URL(s) if necessary
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure SQLAlchemy
Base.metadata.create_all(bind=engine)

app.include_router(router)

tags_metadata = [
    {
        "name": "Authentication",
        "description": "Operations with authenticating users.",
    },
    {
        "name": "Project",
        "description": "Manage projects. CRUD projects and it's subset.",
    },
    {
        "name": "Admin",
        "description": "Operation only admin can do.",
    },
]


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="CarbonSarhat",
        version="1.0.0",
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }

    openapi_schema["security"] = [{"bearerAuth": []}]
    app.openapi_schema = openapi_schema

    for _, method_item in app.openapi_schema.get("paths").items():
        for _, param in method_item.items():
            responses = param.get("responses")
            if "422" in responses:
                del responses["422"]

    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000)  # noqa: F821
