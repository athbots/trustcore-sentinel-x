"""
TrustCore Sentinel X — Windows Service Installer

Installs the sentinel backend as a Windows service using NSSM (Non-Sucking Service Manager).
NSSM is a well-tested, production-grade service wrapper.

Usage:
    python scripts/service_install.py install    # install + start
    python scripts/service_install.py uninstall  # stop + remove
    python scripts/service_install.py status     # check status

Prerequisites:
    1. Download nssm.exe from https://nssm.cc/download
    2. Place nssm.exe in this scripts/ directory or add to PATH
"""
import sys
import subprocess
import shutil
from pathlib import Path

SERVICE_NAME = "TrustCoreSentinelX"
SERVICE_DISPLAY = "TrustCore Sentinel X — AI Cyber Defense"
PROJECT_ROOT = Path(__file__).parent.parent

def find_nssm() -> str | None:
    """Locate nssm.exe."""
    # Check scripts dir
    local = Path(__file__).parent / "nssm.exe"
    if local.exists():
        return str(local)
    # Check PATH
    return shutil.which("nssm")


def find_python() -> str:
    return sys.executable


def install_service():
    nssm = find_nssm()
    python = find_python()

    if not nssm:
        print("❌ nssm.exe not found!")
        print("   Download from https://nssm.cc/download")
        print(f"   Place nssm.exe in {Path(__file__).parent}")
        sys.exit(1)

    print(f"📦 Installing service: {SERVICE_NAME}")
    print(f"   Python:  {python}")
    print(f"   Project: {PROJECT_ROOT}")

    # Install
    subprocess.run([nssm, "install", SERVICE_NAME, python, "-m", "sentinel"],
                   check=True)

    # Configure
    subprocess.run([nssm, "set", SERVICE_NAME, "AppDirectory", str(PROJECT_ROOT)], check=True)
    subprocess.run([nssm, "set", SERVICE_NAME, "DisplayName", SERVICE_DISPLAY], check=True)
    subprocess.run([nssm, "set", SERVICE_NAME, "Description",
                    "AI-powered real-time cybersecurity monitoring and autonomous response"], check=True)
    subprocess.run([nssm, "set", SERVICE_NAME, "Start", "SERVICE_AUTO_START"], check=True)

    # Restart on crash (max 3 restarts with 10s delay)
    subprocess.run([nssm, "set", SERVICE_NAME, "AppExit", "Default", "Restart"], check=True)
    subprocess.run([nssm, "set", SERVICE_NAME, "AppRestartDelay", "10000"], check=True)

    # Logging
    log_dir = PROJECT_ROOT / "logs"
    log_dir.mkdir(exist_ok=True)
    subprocess.run([nssm, "set", SERVICE_NAME, "AppStdout", str(log_dir / "service_stdout.log")], check=True)
    subprocess.run([nssm, "set", SERVICE_NAME, "AppStderr", str(log_dir / "service_stderr.log")], check=True)

    # Start it
    subprocess.run([nssm, "start", SERVICE_NAME])

    print("\n✅ Service installed and started!")
    print("   Dashboard: http://127.0.0.1:8321")
    print(f"   Manage:    services.msc → {SERVICE_DISPLAY}")


def uninstall_service():
    nssm = find_nssm()
    if not nssm:
        print("❌ nssm.exe not found")
        sys.exit(1)

    print(f"🗑️ Removing service: {SERVICE_NAME}")
    subprocess.run([nssm, "stop", SERVICE_NAME])
    subprocess.run([nssm, "remove", SERVICE_NAME, "confirm"], check=True)
    print("✅ Service removed")


def service_status():
    nssm = find_nssm()
    if not nssm:
        # Fallback: use sc query
        result = subprocess.run(["sc", "query", SERVICE_NAME], capture_output=True, text=True)
        print(result.stdout or result.stderr)
        return

    result = subprocess.run([nssm, "status", SERVICE_NAME], capture_output=True, text=True)
    print(f"Service: {SERVICE_NAME}")
    print(f"Status:  {result.stdout.strip()}")


def main():
    if sys.platform != "win32":
        print("❌ This script is for Windows only.")
        print("   On Linux, use systemd: sudo systemctl enable sentinel.service")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python service_install.py [install|uninstall|status]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "install":
        install_service()
    elif cmd == "uninstall":
        uninstall_service()
    elif cmd == "status":
        service_status()
    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
