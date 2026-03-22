import argparse
import subprocess
import sys
import os
import secrets
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# Define directories natively supporting PyInstaller relative offsets
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(sys.executable)

BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
ENV_PATH = os.path.join(BACKEND_DIR, ".env")
DEFAULT_KEY = "trustcore-super-secret-key-2026"

def setup_config():
    """Initializes mathematically secure key environments automatically on first install run."""
    if os.path.exists(ENV_PATH):
        return

    print(f"\n{Fore.CYAN}============================================================")
    print(f"{Fore.CYAN}  🛡️ TrustCore Sentinel X - Initializing Environment...")
    print(f"{Fore.CYAN}============================================================{Style.RESET_ALL}\n")

    new_api_key = secrets.token_hex(24)
    print(f"{Fore.GREEN}✓ Generating secure API key...{Style.RESET_ALL}")
    
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write(f"TRUSTCORE_API_KEY={new_api_key}\n")
    
    print(f"{Fore.GREEN}✓ Writing backend/.env configuration...{Style.RESET_ALL}")

    files_to_patch = [
        os.path.join(ROOT_DIR, "frontend", "app.js"),
        os.path.join(ROOT_DIR, "simulate_demo.py"),
        os.path.join(ROOT_DIR, "simulate_real_data.py"),
        os.path.join(ROOT_DIR, "simulation", "attack_scenarios.py"),
        os.path.join(ROOT_DIR, "tests", "test_api.py")
    ]

    print(f"{Fore.GREEN}✓ Synchronizing local interface keys...{Style.RESET_ALL}")
    for file_path in files_to_patch:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            updated_content = content.replace(DEFAULT_KEY, new_api_key)
            
            if updated_content != content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(updated_content)
                
    print(f"\n{Fore.YELLOW}Setup Complete! System is ready to deploy.{Style.RESET_ALL}\n")


def print_banner():
    """Emit the overarching EDR styled branding graphics directly to terminal stdout."""
    print(f"{Fore.CYAN}{Style.BRIGHT}" + r"""
   _____          __  _            __  _  __
  / ___/___  ____/ /_(_)___  ___  / / | |/ /
  \__ \/ _ \/ __  / / / __ \/ _ \/ /  |   / 
 ___/ /  __/ /_/ / / / / / /  __/ /  /   |  
/____/\___/\__,_/_/_/_/ /_/\___/_/  /_/|_|  
    """)
    print(f"{Fore.WHITE}TrustCore Sentinel X — EDR Orchestrator CLI{Style.RESET_ALL}\n")

def check_python_dependencies():
    """Ensure host dependencies exist if executing natively through interpreter."""
    try:
        import fastapi
        import uvicorn
        import sklearn
    except ImportError:
        print(f"{Fore.RED}ERROR: Core AI/API dependencies are missing. Run `pip install -r requirements.txt`{Style.RESET_ALL}")
        sys.exit(1)

def run_server():
    """Start the FastAPI backend attached to localhost."""
    check_python_dependencies()
    print(f"{Fore.GREEN}Starting TrustCore Sentinel X Daemon...{Style.RESET_ALL}")
    sys.exit(subprocess.call(["python", "-m", "uvicorn", "main:app", "--port", "8000", "--host", "127.0.0.1"], cwd=BACKEND_DIR))

def run_simulate():
    """Start the attack simulator logic demonstrating MITRE chain capabilities."""
    print(f"{Fore.MAGENTA}Launching Interactive Attack Simulator...{Style.RESET_ALL}")
    sys.exit(subprocess.call(["python", "simulate_demo.py"], cwd=ROOT_DIR))

def run_test():
    """Execute Pytest QA ML verification algorithms seamlessly."""
    print(f"{Fore.YELLOW}Executing QA ML Evaluation Pipeline...{Style.RESET_ALL}")
    sys.exit(subprocess.call(["python", "-m", "pytest", "tests/", "-v"], cwd=ROOT_DIR))

def main():
    setup_config()
    
    parser = argparse.ArgumentParser(description="TrustCore Sentinel X Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run", help="Start the main TrustCore backend and UI server")
    subparsers.add_parser("simulate", help="Run the automated multi-stage kill-chain simulation")
    subparsers.add_parser("test", help="Execute the deployment reliability and ML testing suites")
    
    args = parser.parse_args()
    
    print_banner()

    if args.command == "run":
        run_server()
    elif args.command == "simulate":
        run_simulate()
    elif args.command == "test":
        run_test()

if __name__ == "__main__":
    main()
