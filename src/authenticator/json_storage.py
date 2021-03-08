"""Provides an implementation of DICEAuthenticatorStorage that uses an
underlying JSON file to store content

Classes:

 * :class:`JSONAuthenticatorStorage`

Enums:
    STORAGE_KEYS

Raises:
    DICEAuthenticatorStorageException: Exception that occurs during storage operations

"""
"""
 © Copyright 2020-2021 University of Surrey

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
 this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

"""
import json
import logging
import os
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from authenticator.storage import DICEAuthenticatorStorage, DICEAuthenticatorStorageException
from ctap.credential_source import PublicKeyCredentialSource

log = logging.getLogger('debug')


class STORAGE_KEYS():
    """Storage keys enum for referencing the names of the fields
    used in the JSON file
    """
    MASTER_KEY = "master_key"
    SIGNATURE_COUNT = "signature_count"
    CREDENTIALS = "credentials"
    PIN = "pin"
    PIN_RETRIES = "retries"
    PIN_VALUE = "pin_value"
    WRAP_KEY = "wrap_key"
    UV_CHECK_VALUE = "uv_check_value"

class JSONAuthenticatorStorage(DICEAuthenticatorStorage):
    """Concrete implementation of DICEAuthenticatorStorage
    that stores contents in a JSON file
    """
    def __init__(self, path:str):
        super().__init__()
        self._path = path
        if not self._check_exists():
            if not os.path.exists(os.path.dirname(self._path)):
                os.mkdir(os.path.dirname(self._path))
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
        with open(self._path,"r") as file:
            return json.load(file)

    def get_wrapping_key(self)->bytes:
        if STORAGE_KEYS.WRAP_KEY in self._data:
            return bytes.fromhex(self._data[STORAGE_KEYS.WRAP_KEY])
        return None

    def has_wrapping_key(self)->bool:
        return STORAGE_KEYS.WRAP_KEY in self._data

    def set_wrapping_key(self, wrap_key:bytes)->bool:
        self._data[STORAGE_KEYS.WRAP_KEY]=wrap_key.hex()
        return self._write_to_json()

    def get_master_secret(self)->bytes:
        """Gets the master secret

        Should only be called when a master secret exists. Check with
        is_initialised() to determine

        Raises:
            DICEAuthenticatorStorageException: raised if no master secret found

        Returns:
            bytes: master secret as bytes
        """
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

    def debug(self):
        log.debug("")
        log.debug("Starting Storage Debug Output")
        log.debug("=============================")
        log.debug("")
        for relying_party in self._data[STORAGE_KEYS.CREDENTIALS]:
            log.debug("From Relying Party: %s",relying_party)
            rp_debug = []
            for cred in self._data[STORAGE_KEYS.CREDENTIALS][relying_party]:
                credential_source = PublicKeyCredentialSource()
                credential_source.from_bytes(bytes.fromhex(cred))
                rp_debug.append(credential_source.debug())

            log.debug("\t%s", json.dumps(rp_debug,indent=4))

        log.debug("")
        log.debug("Finished Storage Debug Output")
        log.debug("=============================")
        log.debug("")

    def get_signature_counter(self)->int:
        return int.from_bytes(bytes.fromhex(self._data[STORAGE_KEYS.SIGNATURE_COUNT]),"big")

    def _update_signature_counter(self, value:int)->bool:
        self._data[STORAGE_KEYS.SIGNATURE_COUNT]=value.to_bytes(4, 'big')
        return self._write_to_json()

    def update_signature_counter(self, new_counter:int)->bool:
        return self._update_signature_counter(new_counter)

    def increment_signature_counter(self)->bool:
        return self._update_signature_counter(self.get_signature_counter() + 1)

    def add_credential_source(self,rp_id:str,user_id:bytes,
            credential_source:PublicKeyCredentialSource)->bool:
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
            return []
        allowed = None
        check_allowed=False
        #Checks allow list is set and not empty
        if not allow_list is None and allow_list:
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

    def set_pin_retries(self, retries:int)->int:
        self._get_create_pin_retries()
        self._data[STORAGE_KEYS.PIN][STORAGE_KEYS.PIN_RETRIES]=retries
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
        return self._write_to_json()

    def set_uv_value(self, uv_check_value:bytes):
        self._data[STORAGE_KEYS.UV_CHECK_VALUE] = uv_check_value.hex()
        return self._write_to_json()

    def get_uv_value(self)->bytes:
        if STORAGE_KEYS.UV_CHECK_VALUE in self._data:
            return bytes.fromhex(self._data[STORAGE_KEYS.UV_CHECK_VALUE])
        else:
            return None

    def get_string(self, key:str)->str:
        if key in self._data:
            return self._data[key]
        return None

    def delete_field(self, key:str)->bool:
        if key in self._data:
            self._data.pop(key)
            return self._write_to_json()
        return False

    def set_string(self, key:str, data:str)->bool:
        self._data[key] = data
        return self._write_to_json()

    def reset(self)->bool:
        self._data={"_version":"JSONAuthenticatorStorage_0.1"}
        self._data[STORAGE_KEYS.CREDENTIALS]={}
        self._write_to_json()
        return self.init_new()

    def _write_to_json(self):
        try:
            with open(self._path,"w") as file:
                json.dump(self._data, file, indent = 4)
            return True
        except EnvironmentError:
            log.error("IO Exception writing JSON", exc_info=True)
            return False


class EncryptedJSONAuthenticatorStorage(JSONAuthenticatorStorage):
    """Concrete implementation of DICEAuthenticatorStorage
    that stores contents in an encrypted JSON file
    """
    def __init__(self, path:str, pwd:str):
        self._key = None
        self._salt = None
        self._prep_crypto(pwd,path)
        super().__init__(path)

    def _prep_crypto(self,pwd:str, path:str)->bytes:
        """Derives the encryption key from the password

        Args:
            pwd (str): Password

        Returns:
            bytes: base64 encoded fernet encryption key
        """

        if os.path.exists(path):
            with open(path,"rb") as file:
                self._salt = file.read(16)
        else:
            self._salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                length=32,salt=self._salt,iterations=100000,backend=default_backend())
        self._key = base64.urlsafe_b64encode(kdf.derive(pwd.encode("UTF-8")))

    def _write_to_json(self):
        try:
            data = json.dumps(self._data)
            fernet = Fernet(self._key)
            token = fernet.encrypt(data.encode("UTF-8"))
            with open(self._path,"wb") as file:
                file.write(self._salt)
                file.write(token)
            return True
        except EnvironmentError:
            log.error("IO Exception writing Encrypted JSON", exc_info=True)
            return False

    def _read_from_json(self):
        data = None
        with open(self._path,"rb") as file:
            self._salt = file.read(16)
            data = file.read()

        fernet = Fernet(self._key)
        return json.loads(str(fernet.decrypt(data),"UTF-8"))
