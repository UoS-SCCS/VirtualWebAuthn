import json
import logging
import os 
from DICEAuthenticatorStorage import DICEAuthenticatorStorage
from DICEAuthenticatorStorage import DICEAuthenticatorStorageException
from PublicKeyCredentialSource import PublicKeyCredentialSource
from abc import ABC
from enum import Enum, unique
log = logging.getLogger('debug')
class STORAGE_KEYS():
    MASTER_KEY = "master_key"
    SIGNATURE_COUNT = "signature_count"
    CREDENTIALS = "credentials"
    PIN = "pin"
    PIN_RETRIES = "retries"
    PIN_VALUE = "pin_value"


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
            self._data[STORAGE_KEYS.CREDENTIALS][rp_id]= []
        self._data[STORAGE_KEYS.CREDENTIALS][rp_id].append(credential_source.get_bytes().hex())
        return self._write_to_json()

    def get_credential_source(self,rp_id:str,user_id:bytes)->PublicKeyCredentialSource:
        if not rp_id in self._data[STORAGE_KEYS.CREDENTIALS]:
            return None
        return self.get_credential_source_by_rp(rp_id,[{"id":user_id,"type":"public-key"}])

    def get_credential_source_by_rp(self,rp_id:str,allow_list=None)->{PublicKeyCredentialSource}:
        if not rp_id in self._data[STORAGE_KEYS.CREDENTIALS]:
            return None
        allowed = None
        check_allowed=False
        if not allow_list is None:
            allowed = self.convert_allow_list_to_map(allow_list)
            check_allowed=True
        results = []
        for value in self._data[STORAGE_KEYS.CREDENTIALS][rp_id]:
            credential_source = PublicKeyCredentialSource()
            credential_source.from_bytes(bytes.fromhex(value))
            if check_allowed:
                if credential_source.get_id() in allowed:
                    results.append(credential_source)
            else:
                #not allowed list, return everything
                results.append(credential_source)
        return results

    def _get_create_pin(self):
        if not STORAGE_KEYS.PIN in self._data:
            self._data[STORAGE_KEYS.PIN]={}
            self._write_to_json()
        return self._data[STORAGE_KEYS.PIN]
    
    def _get_create_pin_retries(self):
        pin = self._get_create_pin()
        if not STORAGE_KEYS.PIN_RETRIES in pin:
            pin[STORAGE_KEYS.PIN_RETRIES]=8
            self._write_to_json()
        return pin[STORAGE_KEYS.PIN_RETRIES]

    def get_pin_retries(self)->int:
        return self._get_create_pin_retries()
        
    def set_pin_retries(self, new_value:int)->int:
        self._get_create_pin_retries()
        self._data[STORAGE_KEYS.PIN][STORAGE_KEYS.PIN_RETRIES]=new_value
        self._write_to_json()
        return self._data[STORAGE_KEYS.PIN][STORAGE_KEYS.PIN_RETRIES]

    def decrement_pin_retries(self)->int:
        self._get_create_pin_retries()
        self._data[STORAGE_KEYS.PIN][STORAGE_KEYS.PIN_RETRIES]-=1
        self._write_to_json()
        return self._data[STORAGE_KEYS.PIN][STORAGE_KEYS.PIN_RETRIES]

    def get_pin(self)->bytes:
        pin = self._get_create_pin()
        if STORAGE_KEYS.PIN_VALUE in pin:
            return bytes.fromhex(pin[STORAGE_KEYS.PIN_VALUE])
        else:
            return None
    def set_pin(self, pin_value:bytes):
        pin = self._get_create_pin()
        pin[STORAGE_KEYS.PIN_VALUE]=pin_value.hex()
        self.set_pin_retries(8)
        self._write_to_json()

    def reset(self)->bool:
        self._data={"_version":"JSONAuthenticatorStorage_0.1"}
        self._data[STORAGE_KEYS.CREDENTIALS]={}
        self._write_to_json()
        return self.init_new()

    def _write_to_json(self):
        try:
            with open(self._path,"w") as f:
                json.dump(self._data, f, indent = 4)
            return True
        except EnvironmentError:
            log.error("IO Exception writing JSON", exc_info=True)
            return False
