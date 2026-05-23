from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Adversarial Arena API",
    version="0.1.0",
    description="API skeleton for a blue-vs-red simulation and scoring workflow."
)

class HealthResponse(BaseModel):
    status: str
    service: str

@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(status="ok", service="adversarial-arena")

@app.get("/api/v1/summary")
def summary():
    return {
        "project": "Adversarial Arena",
        "mode": "skeleton",
        "message": "Replace mocked handlers with real red-team, blue-team, and scoring logic."
    }
