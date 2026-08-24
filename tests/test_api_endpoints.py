import sys
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from backend.app import app

def test_api():
    client = TestClient(app)

    # 1. Test status
    resp = client.get("/api/status")
    assert resp.status_code == 200, f"Status failed: {resp.status_code}"
    data = resp.json()
    assert data["status"] == "ONLINE"
    print("  [+] GET /api/status -> ONLINE")

    # 2. Test canary tokens
    resp = client.get("/api/canary/tokens")
    assert resp.status_code == 200
    tokens = resp.json()
    assert len(tokens) >= 5
    print(f"  [+] GET /api/canary/tokens -> {len(tokens)} tokens active")

    # 3. Test shell exec endpoint
    resp = client.post("/api/shell/exec", json={"session_id": "api-test-01", "command": "uname -a"})
    assert resp.status_code == 200
    res_data = resp.json()
    assert "Linux" in res_data["stdout"]
    print("  [+] POST /api/shell/exec -> Success")

    # 4. Test decoy web endpoint (/.env)
    resp = client.get("/.env")
    assert resp.status_code == 200
    assert "DATABASE_URL" in resp.text
    print("  [+] GET /.env (Decoy Bait) -> Served fake canary secrets")

    # 5. Test MITRE matrix endpoint
    resp = client.get("/api/mitre/matrix")
    assert resp.status_code == 200
    print("  [+] GET /api/mitre/matrix -> Success")

    # 6. Test index.html serving
    resp = client.get("/")
    assert resp.status_code == 200
    assert "NEURAL HONEYGRID" in resp.text
    print("  [+] GET / (Frontend Dashboard) -> Rendered successfully")

    print("\n[✓] All API and Decoy Endpoints Verified!")

if __name__ == "__main__":
    test_api()
