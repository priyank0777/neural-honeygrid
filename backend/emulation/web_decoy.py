import time
from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from backend.canary.honeytokens import honeytoken_manager
from backend.intelligence.mitre_mapper import MitreTechnique

web_decoy_router = APIRouter()

@web_decoy_router.get("/.env")
async def decoy_env(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    honeytoken_manager.check_for_canary_access(
        session_id=f"web-{client_ip}",
        target_path_or_content="/opt/api_gateway/.env",
        command=f"HTTP GET /.env from {client_ip}"
    )
    content = (
        "# Production Environment Configuration\n"
        "NODE_ENV=production\n"
        "DATABASE_URL=postgres://superadmin:P@ssw0rd_Canary_2024!@10.0.4.12:5432/core_production\n"
        "AWS_ACCESS_KEY_ID=AKIA_PROD_SEC_BAIT_94X7F\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_BAIT_992\n"
        "JWT_SECRET=SUPER_SECRET_INTERNAL_CANARY_JWT_SIGNING_KEY_9921\n"
    )
    return PlainTextResponse(content, status_code=200)

@web_decoy_router.get("/admin")
@web_decoy_router.get("/login")
async def decoy_login(request: Request):
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CorpSec Master Admin Portal</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
            .login-card { background: #1e293b; padding: 2.5rem; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); width: 360px; border: 1px solid #334155; }
            h2 { margin-top: 0; color: #38bdf8; font-size: 1.5rem; text-align: center; }
            p { font-size: 0.85rem; color: #94a3b8; text-align: center; margin-bottom: 2rem; }
            .input-group { margin-bottom: 1.25rem; }
            label { display: block; margin-bottom: 0.5rem; font-size: 0.85rem; color: #cbd5e1; }
            input { width: 100%; padding: 0.75rem; background: #0f172a; border: 1px solid #475569; border-radius: 6px; color: #fff; box-sizing: border-box; }
            button { width: 100%; padding: 0.75rem; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; margin-top: 1rem; }
            button:hover { background: #1d4ed8; }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h2>🛡️ CorpSec Gateway</h2>
            <p>Authorized personnel only. All access attempts are recorded.</p>
            <form method="POST" action="/api/v1/auth/login">
                <div class="input-group">
                    <label>Username / Employee ID</label>
                    <input type="text" name="username" placeholder="admin@corp.internal" required />
                </div>
                <div class="input-group">
                    <label>Master Security Key</label>
                    <input type="password" name="password" placeholder="••••••••••••" required />
                </div>
                <button type="submit">Sign In to Dashboard</button>
            </form>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html, status_code=200)

@web_decoy_router.post("/api/v1/auth/login")
async def decoy_auth_handler(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    form_data = await request.form() if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded") else {}
    username = form_data.get("username", "unknown")
    
    # Log failed intrusion attempt
    honeytoken_manager.check_for_canary_access(
        session_id=f"web-{client_ip}",
        target_path_or_content=f"login attempt: {username}",
        command=f"Web Auth Brute Force attempt user={username}"
    )
    return JSONResponse(
        {"status": "error", "code": "AUTH_MFA_REQUIRED", "message": "Hardware Security Token / YubiKey MFA Challenge required for remote IP."},
        status_code=401
    )

@web_decoy_router.get("/actuator/env")
@web_decoy_router.get("/api/v1/debug")
async def decoy_actuator(request: Request):
    return JSONResponse({
        "profiles": ["production", "cloud-internal"],
        "server.port": 8000,
        "spring.datasource.url": "jdbc:postgresql://10.0.4.12:5432/core_production",
        "spring.datasource.username": "superadmin",
        "spring.datasource.password": "P@ssw0rd_Canary_2024!",
        "aws.region": "us-east-1"
    })
