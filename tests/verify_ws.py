import asyncio
import websockets
import sys

async def test_ws_auth():
    uri_valid = "ws://localhost:8000/ws/feed?api_key=trustcore-super-secret-key-2026"
    uri_invalid = "ws://localhost:8000/ws/feed?api_key=wrong-key"
    
    print("Testing INVALID key...")
    try:
        async with websockets.connect(uri_invalid) as websocket:
            print("ERROR: Connected with invalid key!")
            sys.exit(1)
    except websockets.exceptions.ConnectionClosed as e:
        print(f"OK: Connection closed as expected. Code: {e.code}")
        if e.code != 1008:
            print(f"WARNING: Expected code 1008, got {e.code}")
    except Exception as e:
        print(f"Interpreted failure (could be server not running): {e}")

    print("\nTesting VALID key...")
    try:
        async with websockets.connect(uri_valid) as websocket:
            print("OK: Connected successfully with valid key!")
            await websocket.send("ping")
            resp = await websocket.recv()
            print(f"Server response: {resp}")
    except Exception as e:
        print(f"FAILED to connect with valid key: {e}")

if __name__ == "__main__":
    # This script assumes the server is running on localhost:8000
    # Since we can't easily start the server and wait for it in one go without blocking,
    # we'll just check if it's reachable.
    asyncio.run(test_ws_auth())
