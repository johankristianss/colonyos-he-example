import json
import base64
from phe import paillier

# Generate public and private keys for Paillier encryption
public_key, private_key = paillier.generate_paillier_keypair()

# Serialize keys to JSON format
public_key_json = json.dumps({'n': str(public_key.n)})
private_key_json = json.dumps({'p': str(private_key.p), 'q': str(private_key.q)})

# Encode the entire JSON string in base64
public_key_b64 = base64.b64encode(public_key_json.encode()).decode('utf-8')
private_key_b64 = base64.b64encode(private_key_json.encode()).decode('utf-8')

# Save the base64 encoded public key to a file
with open('public_key.b64', 'w') as f:
    f.write(public_key_b64)

# Save the base64 encoded private key to a file
with open('private_key.b64', 'w') as f:
    f.write(private_key_b64)

