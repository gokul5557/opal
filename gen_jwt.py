
import json
import base64
import sys

def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    return encoded.rstrip('=')

header = {"alg": "HS256", "typ": "JWT"}
payload = {"email": "alice@sagasoft.io"}

# Use compact separators (no spaces)
token_head = base64url_encode(json.dumps(header, separators=(',', ':')))
token_payload = base64url_encode(json.dumps(payload, separators=(',', ':')))
signature = "dummy_signature"

print(f"{token_head}.{token_payload}.{signature}", end="")
