import httpx
import time
import json
from uuid import uuid4

# Auth Service endpoint (change if running elsewhere)
AUTH_URL = "http://localhost:8000/api/v1/auth/register"

# Generate unique credentials using timestamp + random
timestamp = int(time.time())
email = f"test+{timestamp}@example.com"
username = f"user{timestamp}"

payload = {
    "email": email,
    "username": username,
    "password": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User",
    "timezone": "Africa/Lagos",
    "language": "en"
}

headers = {
    "Content-Type": "application/json",
    "Idempotency-Key": str(uuid4())   # unique each run
}

print(f"🔍 Sending registration request to {AUTH_URL}")
print(f"📦 Payload: {json.dumps(payload, indent=2)}")
print(f"🔑 Idempotency-Key: {headers['Idempotency-Key']}\n")

try:
    start = time.time()
    with httpx.Client(timeout=30) as client:
        resp = client.post(AUTH_URL, json=payload, headers=headers)
    elapsed = time.time() - start

    print(f"⏱️  Response time: {elapsed:.2f}s")
    print(f"📊 HTTP Status: {resp.status_code} {resp.reason_phrase}")
    print(f"📄 Response body:\n{resp.text}")

    if resp.status_code == 503:
        print("\n⚠️  503 Service Unavailable – check the Auth Service logs.")
        print("   Look for 'IntegrationError' or 'httpx.HTTPError' in the server console.")
    elif resp.status_code == 201:
        print("\n✅ Registration successful!")
    elif resp.status_code == 409:
        print("\n⚠️  User already exists – try again (the timestamp ensures uniqueness, so this is unlikely).")
    else:
        print("\n❓ Unexpected status – investigate server logs.")

except Exception as e:
    print(f"\n💥 Exception: {repr(e)}")