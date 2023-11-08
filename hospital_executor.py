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
    def __init__(self, executortype, patient_data):
        crypto = Crypto()
        
        colonies, colonyid, colony_prvkey, _, _ = colonies_client()

        self.colonies = colonies
        self.colonyid = colonyid
        self.colony_prvkey = colony_prvkey
        self.executor_prvkey = crypto.prvkey()
        self.executorid = crypto.id(self.executor_prvkey)
        self.patient_data = patient_data
        self.executortype = executortype

        self.register()
        
    def register(self):
        executor = {
            "executorname": "hospital-executor" + str(uuid.uuid4()),
            "executorid": self.executorid,
            "colonyid": self.colonyid,
            "executortype": self.executortype
        }

        try:
            self.colonies.add_executor(executor, self.colony_prvkey)
            self.colonies.approve_executor(self.executorid, self.colony_prvkey)
        except Exception as err:
            print(err)
            os._exit(-1)
        print("Executor", self.executorid, "registered")
        
        try:
            self.colonies.add_function(self.executorid, 
                                       self.colonyid, 
                                       "get_patient_data",  
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
                process = self.colonies.assign(self.colonyid, 10, self.executor_prvkey)
                print("Process", process["processid"], "is assigned to executor")
                if process["spec"]["funcname"] == "get_patient_data":
                    public_key = self.get_pubkey(process)

                    encrypted_value = public_key.encrypt(int(self.patient_data))
                    encrypted_value_b64 = base64.b64encode(str(encrypted_value.ciphertext()).encode()).decode('utf-8')

                    self.colonies.close(process["processid"], [encrypted_value_b64], self.executor_prvkey)
            except Exception as err:
                print(err)
                pass

    def unregister(self):
        self.colonies.delete_executor(self.executorid, self.colony_prvkey)
        print("Executor", self.executorid, "unregistered")
        os._exit(0)

def sigint_handler(signum, frame):
    executor.unregister()

if __name__ == '__main__':
    executortype = sys.argv[1]
    patient_data = sys.argv[2]
    signal.signal(signal.SIGINT, sigint_handler)
    executor = PythonExecutor(executortype, patient_data)
    executor.start()
