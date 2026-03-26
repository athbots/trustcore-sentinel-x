import asyncio
import httpx
import json
import time

API_URL = "http://127.0.0.1:8080/api/v1/evaluate"

async def send_eval(client, desc, payload):
    print(f"\n[{desc}] Sending...")
    try:
        start = time.perf_counter()
        resp = await client.post(API_URL, json=payload, timeout=5.0)
        latency = (time.perf_counter() - start) * 1000
        print(f"Response ({latency:.2f}ms):")
        print(json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"API Error - Is the engine running? {e}")

async def run_simulations():
    print("==============================================")
    print("   TRUSTCORE SENTINEL™ - PROD VALIDATION")
    print("==============================================\n")
    
    async with httpx.AsyncClient() as client:
        # Scenario 1: Normal Safe Login
        await send_eval(client, "TEST 1: Normal User Login", {
            "user_id": "emp_john_doe",
            "session_id": "sess123",
            "device_id": "dev_corp_mac",
            "ip_address": "192.168.1.50",
            "action": "login",
            "content": "None"
        })
        
        # Scenario 2: Phishing Content (Transformer NLP validation)
        await send_eval(client, "TEST 2: Spear-Phishing / Payload Injection", {
            "user_id": "emp_john_doe",
            "session_id": "sess123",
            "device_id": "dev_corp_mac",
            "ip_address": "8.8.8.8", # Unknown external IP
            "action": "upload",
            "content": "Subject: Urgent Invoice.\nPlease execute the attached script> drop table users; --"
        })
        
        # Scenario 3: Bot Spike (Abnormal Behavior / Spike)
        print("\n[TEST 3: Bot Credential Stuffing / Spike]")
        for i in range(1, 6):
            payload = {
                "user_id": f"emp_john_doe",
                "session_id": f"sess_bot_{i}",
                "device_id": "dev_unknown_botnet",
                "ip_address": f"10.0.0.{i}",
                "action": "login",
                "content": "None"
            }
            if i == 5:
                await send_eval(client, "Final Spike Request (Anomaly Triggered)", payload)
            else:
                # Fire and forget for rate accumulation
                asyncio.create_task(client.post(API_URL, json=payload))
                await asyncio.sleep(0.05)
                
if __name__ == "__main__":
    asyncio.run(run_simulations())
