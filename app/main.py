"""Punto de entrada FastAPI de Omni-CleanerMail."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import config
from app.api import routes
from app.core import auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth.init_db()
    from app.core import hashchain as hc
    from app.mail import addressbook, engines, findings, ksmg, quarantine, reports
    engines.init_engines()
    engines.seed_default_signatures()
    quarantine.init_quarantine()
    addressbook.init_addressbook()
    findings.init_findings()
    ksmg.init_ksmg()
    cfg = ksmg.load_config()
    if cfg.get("auto_arranque") and cfg.get("modo") != "SIMULADO":
        ksmg.start_poller()
    reports.init_reports()
    reports.start_poller()
    hc.append("system_start", "SISTEMA", {"service": "Omni-CleanerMail"})
    yield


app = FastAPI(title="Omni-CleanerMail", version="1.0.0", docs_url="/docs",
              openapi_url="/openapi.json", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if config.DEMO_MODE else [],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router)

UI_DIR = config.BASE_DIR / "app" / "ui" / "static"
app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(UI_DIR / "index.html"))