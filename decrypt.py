
from pycolonies import Crypto
from pycolonies import Colonies
from pycolonies import colonies_client
from phe import paillier
import base64
from phe import paillier
import json
import sys

def get_pubkey(process):
    public_key_b64 = process["spec"]["kwargs"]["paillier-pubkey"]

    public_key_json = base64.b64decode(public_key_b64).decode('utf-8')
    public_key_data = json.loads(public_key_json)
    return paillier.PaillierPublicKey(n=int(public_key_data['n']))

if __name__ == '__main__':
    processid = sys.argv[1]

    colonies, colonyid, colony_prvkey, executorid, executor_prvkey = colonies_client()
    process = colonies.get_process(processid, executor_prvkey)
    public_key = get_pubkey(process)
    encrypted_sum_b64 = process["out"][0]
    encrypted_sum_bytes = base64.b64decode(encrypted_sum_b64)
    encrypted_sum_str = encrypted_sum_bytes.decode('utf-8')
    encrypted_sum_int = int(encrypted_sum_str)
    encrypted_sum2 = paillier.EncryptedNumber(public_key, encrypted_sum_int)

    with open('private_key.b64', 'r') as f:
        private_key_b64 = f.read()
        private_key_json = base64.b64decode(private_key_b64).decode('utf-8')
        private_key_data = json.loads(private_key_json)
        private_key = paillier.PaillierPrivateKey(public_key, p=int(private_key_data['p']), q=int(private_key_data['q']))
    
    total_sum = private_key.decrypt(encrypted_sum2)

    print(f"The sum of all patient data is: {total_sum}")
