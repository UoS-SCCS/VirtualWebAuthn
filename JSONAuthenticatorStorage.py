import json
import logging
import os 
from DICEAuthenticatorStorage import DICEAuthenticatorStorage
from DICEAuthenticatorStorage import DICEAuthenticatorStorageException
from PublicKeyCredentialSource import PublicKeyCredentialSource
from abc import ABC
from enum import Enum, unique

class STORAGE_KEYS():
    MASTER_KEY = "master_key"
    SIGNATURE_COUNT = "signature_count"
    CREDENTIALS = "credentials"

class JSONAuthenticatorStorage(DICEAuthenticatorStorage):
    def __init__(self, path:str):
        self._path = path
        if not self._check_exists():
            self._data={"_version":"JSONAuthenticatorStorage_0.1"}
            self._data[STORAGE_KEYS.CREDENTIALS]={}
            self._write_to_json()
        self._data = self._read_from_json()


    def is_initialised(self)->bool:
        if STORAGE_KEYS.SIGNATURE_COUNT in self._data and STORAGE_KEYS.MASTER_KEY in self._data:
            return True
        else:
            return False

    def _check_exists(self):
        return os.path.exists(self._path)
    
    def _read_from_json(self):
        with open(self._path,"r") as f:
            return json.load(f)

    
    def get_master_secret(self)->bytes:
        if STORAGE_KEYS.MASTER_KEY in self._data:
            return bytes.fromhex(self._data[STORAGE_KEYS.MASTER_KEY])
        else:
            raise DICEAuthenticatorStorageException("No master secret set")
            
    def init_new(self,master_secret:bytes=None)->bool:
        if master_secret is None:
            self._data[STORAGE_KEYS.MASTER_KEY]=os.urandom(64).hex()
        else:
            self._data[STORAGE_KEYS.MASTER_KEY]=master_secret
        self._data[STORAGE_KEYS.SIGNATURE_COUNT]=b'\x00\x00\x00\x00'.hex()
        return self._write_to_json()    

    def get_signature_counter(self)->int:
        return int.from_bytes(bytes.fromhex(self._data[STORAGE_KEYS.SIGNATURE_COUNT]),"big")

    def _update_signature_counter(self, value:int)->bool:
        self._data[STORAGE_KEYS.SIGNATURE_COUNT]=value.to_bytes(4, 'big')
        return self._write_to_json()
    
    def update_signature_counter(self, new_counter:int)->bool:
        return self._update_signature_counter(new_counter)
    
    def increment_signature_counter(self)->bool:
        return self._update_signature_counter(self.get_signature_counter() + 1)
    
    def add_credential_source(self,rp_id:str,user_id:bytes, credential_source:PublicKeyCredentialSource)->bool:
        if not rp_id in self._data[STORAGE_KEYS.CREDENTIALS]:
            self._data[STORAGE_KEYS.CREDENTIALS][rp_id]= {}
        
        user_id_str = user_id.hex()
        self._data[STORAGE_KEYS.CREDENTIALS][rp_id][user_id_str]= credential_source.get_bytes().hex()
        return self._write_to_json()

    def get_credential_source(self,rp_id:str,user_id:bytes)->PublicKeyCredentialSource:
        if not rp_id in self._data[STORAGE_KEYS.CREDENTIALS]:
            return None
        user_id_str = user_id.hex()
        credential_source = PublicKeyCredentialSource()
        credential_source.from_bytes(bytes.fromhex(self._data[STORAGE_KEYS.CREDENTIALS][rp_id][user_id_str]))

    def get_credential_source_by_rp(self,rp_id:str)->{PublicKeyCredentialSource}:
        if not rp_id in self._data[STORAGE_KEYS.CREDENTIALS]:
            return None
        results = {}
        for key, value in self._data[STORAGE_KEYS.CREDENTIALS][rp_id].items():
            credential_source = PublicKeyCredentialSource()
            credential_source.from_bytes(bytes.fromhex(value))
            results[key]=credential_source
        return results

    def _write_to_json(self):
        try:
            with open(self._path,"w") as f:
                json.dump(self._data, f, indent = 4)
            return True
        except EnvironmentError:
            logging.error("IO Exception writing JSON", exc_info=True)
            return False
