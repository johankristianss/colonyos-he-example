from pycolonies import Crypto
from pycolonies import Colonies
from pycolonies import colonies_client
import signal
import os
import uuid 
import base64
from phe import paillier
import json
import sys

class PythonExecutor:
    def __init__(self):
        crypto = Crypto()
        
        colonies, colonyname, colony_prvkey, _, _ = colonies_client()

        self.colonies = colonies
        self.colonyname = colonyname
        self.colony_prvkey = colony_prvkey
        self.executor_prvkey = crypto.prvkey()
        self.executorid = crypto.id(self.executor_prvkey)
        self.executorname = "hospital-executor" + str(uuid.uuid4())

        self.register()
        
    def register(self):
        executor = {
            "executorname": self.executorname,
            "executorid": self.executorid,
            "colonyname": self.colonyname,
            "executortype": "cloud-hospital-executor"
        }

        try:
            self.colonies.add_executor(executor, self.colony_prvkey)
            self.colonies.approve_executor(self.colonyname, self.executorname, self.colony_prvkey)
        except Exception as err:
            print(err)
            os._exit(-1)
        print("Executor", self.executorid, "registered")
        
        try:
            self.colonies.add_function(self.executorname, 
                                       self.colonyname, 
                                       "sum_patient_data",  
                                       self.executor_prvkey)
            
        except Exception as err:
            print(err)
    
    def get_pubkey(self, process):
        public_key_b64 = process["spec"]["kwargs"]["paillier-pubkey"]
        public_key_json = base64.b64decode(public_key_b64).decode('utf-8')
        public_key_data = json.loads(public_key_json)
        return paillier.PaillierPublicKey(n=int(public_key_data['n']))

    def start(self):
        while (True):
            try:
                process = self.colonies.assign(self.colonyname, 10, self.executor_prvkey)
                print("Process", process["processid"], "is assigned to executor")
                if process["spec"]["funcname"] == "sum_patient_data":
                    public_key = self.get_pubkey(process)

                    encrypted_data_b64 = process["in"]
                    encrypted_data = [paillier.EncryptedNumber(public_key, int(base64.b64decode(data_b64))) for data_b64 in encrypted_data_b64]
                   
                    encrypted_sum = sum(encrypted_data, start=public_key.encrypt(0))
                    encrypted_sum_b64 = base64.b64encode(str(encrypted_sum.ciphertext()).encode()).decode('utf-8')

                    self.colonies.close(process["processid"], [encrypted_sum_b64], self.executor_prvkey)
            except Exception as err:
                print(err)
                pass

    def unregister(self):
        self.colonies.remove_executor(self.colonyname, self.executorname, self.colony_prvkey)
        print("Executor", self.executorid, "unregistered")
        os._exit(0)

def sigint_handler(signum, frame):
    executor.unregister()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, sigint_handler)
    executor = PythonExecutor()
    executor.start()
