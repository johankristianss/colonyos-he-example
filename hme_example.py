import json
import base64
from phe import paillier

# Read the base64 encoded public key from a file and decode it
with open('public_key.b64', 'r') as f:
    public_key_b64 = f.read()
    public_key_json = base64.b64decode(public_key_b64).decode('utf-8')
    public_key_data = json.loads(public_key_json)
    public_key = paillier.PaillierPublicKey(n=int(public_key_data['n']))

# Read the base64 encoded private key from a file and decode it
with open('private_key.b64', 'r') as f:
    private_key_b64 = f.read()
    private_key_json = base64.b64decode(private_key_b64).decode('utf-8')
    private_key_data = json.loads(private_key_json)
    private_key = paillier.PaillierPrivateKey(public_key, p=int(private_key_data['p']), q=int(private_key_data['q']))

# Now you can use public_key and private_key for encryption and decryption
private_data = {
    'site1': 15,
    'site2': 25,
    'site3': 35
}

# Encrypt each site's private data using the public key
encrypted_data = [public_key.encrypt(value) for value in private_data.values()]

encrypted_data_b64 = [base64.b64encode(str(data.ciphertext()).encode()).decode('utf-8') for data in encrypted_data]

print(encrypted_data_b64)

encrypted_data2 = [paillier.EncryptedNumber(public_key, int(base64.b64decode(data_b64))) for data_b64 in encrypted_data_b64]

# The central authority sums the encrypted values
encrypted_sum = sum(encrypted_data2, start=public_key.encrypt(0))
encrypted_sum_b64 = base64.b64encode(str(encrypted_sum.ciphertext()).encode()).decode('utf-8')
print(encrypted_sum_b64)

encrypted_sum_bytes = base64.b64decode(encrypted_sum_b64)

# Convert bytes to string and then to an integer
encrypted_sum_str = encrypted_sum_bytes.decode('utf-8')
encrypted_sum_int = int(encrypted_sum_str)
encrypted_sum2 = paillier.EncryptedNumber(public_key, encrypted_sum_int)


# The encrypted sum is then decrypted with the private key
total_sum = private_key.decrypt(encrypted_sum2)

print(f"The sum of all site data is: {total_sum}")
