"""Contains the TPM classes for interfacing with the C TPM wrapper

Includes a series of C structs for use with ctypes and various
wrapper classes as well as the core TPM class

Structs:

 * :class:`ByteArrayStr`
 * :class:`KeyData`
 * :class:`KeyECCPoint`
 * :class:`RelyingPartyKey`
 * :class:`ECDSASig`

Wrapper Classes:

 * :class:`DICEECDSASig`
 * :class:`DICEKeyPoint`
 * :class:`DICERelyingPartyKey`
 * :class:`DICEKeyData`

Classes:
 * :class:`TPM`
 * :class:`TPMException`

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
import ctypes
import os



from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ec import (EllipticCurvePublicKey,
    EllipticCurvePublicNumbers)
from cryptography.hazmat.backends import default_backend

class ByteArray(ctypes.Structure):
    """Ctypes structure for ByteArray
    """
    _fields_ = [('size', ctypes.c_uint16),
                ('data', ctypes.POINTER(ctypes.c_byte))]

class ByteArrayStr(ctypes.Structure):
    """Ctypes structure for ByteArray that contains a
    string.
    """
    _fields_ = [('size', ctypes.c_uint16),
                ('data', ctypes.c_char_p)]


class KeyData(ctypes.Structure):
    """Ctypes structure for key pair, consisting of a
    public_data ByteArray and a private_data ByteArray
    """
    _fields_ = [('public_data', ByteArray),
                ('private_data', ByteArray)]

class KeyECCPoint(ctypes.Structure):
    """Ctypes structure that represents an EC point

    Contains a x_coord ByteArray and a
    y_coord ByteArray
    """
    _fields_ = [('x_coord', ByteArray),
                ('y_coord', ByteArray)]

class RelyingPartyKey(ctypes.Structure):
    """Ctypes structure representing a Relying Party
    key, consisting of a key_blob KeyData and a
    key_point KeyECCPoint containing the Public Key
    """
    _fields_ = [('key_blob', KeyData),
                ('key_point', KeyECCPoint)]

class ECDSASig(ctypes.Structure):
    """Ctypes structure for a DSA signature,
    consisting of a r ByteArray, and an s ByteArray
    """
    _fields_ = [('sig_r', ByteArray),
                ('sig_s', ByteArray)]


class DICEECDSASig():
    """Class to hold the ECDSA Signature
    Provides a function to return it to a valid ctypes
    structure
    """
    def __init__(self, tpm_sig:ECDSASig):
        self.sig_r = bytes(ctypes.string_at(tpm_sig.sig_r.data,
            ctypes.sizeof(ctypes.c_byte) * tpm_sig.sig_r.size))
        self.sig_s = bytes(ctypes.string_at(tpm_sig.sig_s.data,
            ctypes.sizeof(ctypes.c_byte) * tpm_sig.sig_s.size))


    def get_as_ecdsa_struct(self)->ECDSASig:
        """Gets the signature as a ctypes ECDSASig structure so
        that it can be passed back to C

        Returns:
            ECDSASig: C structure containing signature
        """
        ptr_r = ctypes.cast(self.sig_r, ctypes.POINTER(ctypes.c_byte))
        sig_r_ba = ByteArray(len(self.sig_r),ptr_r)
        ptr_s = ctypes.cast(self.sig_s, ctypes.POINTER(ctypes.c_byte))
        sig_s_ba = ByteArray(len(self.sig_s),ptr_s)
        return ECDSASig(sig_r_ba,sig_s_ba)

    def get_as_der_encoded_signature(self)->bytes:
        """Encodes the signature in a python compatible DER format

        Returns:
            bytes: signature as DER bytes
        """
        return utils.encode_dss_signature(int(self.sig_r.hex(), 16), int(self.sig_s.hex(), 16))

class DICEKeyPoint():
    """Holds a reference to an EC point and provides a method to encode it
    as a ctypes KeyECCPoint to be passed to C
    """
    def __init__(self, point:KeyECCPoint, empty=False):
        if empty:
            return
        self.x_point = bytes(ctypes.string_at(point.x_coord.data,
            ctypes.sizeof(ctypes.c_byte) * point.x_coord.size))
        self.y_point = bytes(ctypes.string_at(point.y_coord.data,
            ctypes.sizeof(ctypes.c_byte) * point.y_coord.size))

    def as_json(self)->dict:
        """Generates a JSON compatible dictionary for storing

        Returns:
            dict: dictionary contain x and y
        """
        out = {}
        out["x"] = self.x_point.hex()
        out["y"] = self.y_point.hex()
        return out

    @classmethod
    def from_json(cls, load:dict)->'DICEKeyPoint':
        """Creates an instace from JSON

        Returns:
            DICEKeyPoint: new instance from JSON
        """
        new_key_point = DICEKeyPoint(None,True)
        new_key_point.x_point = bytes.fromhex(load["x"])
        new_key_point.y_point = bytes.fromhex(load["y"])
        return new_key_point

    def get_as_key_ec_point_struct(self)->KeyECCPoint:
        """Encodes the EC Point as a KeyECCPoint ctypes structure

        Returns:
            KeyECCPoint: Structure to be passed to C
        """
        ptr_pub = ctypes.cast(self.x_point, ctypes.POINTER(ctypes.c_byte))
        x_data_ba = ByteArray(len(self.x_point),ptr_pub)
        ptr_prv = ctypes.cast(self.y_point, ctypes.POINTER(ctypes.c_byte))
        y_data_ba = ByteArray(len(self.y_point),ptr_prv)
        return KeyECCPoint(x_data_ba,y_data_ba)

class DICERelyingPartyKey():
    """Holds a constructed Relying Party Key. Provides
    utility methods for encoding as a RelyingPartyKey structure
    and for storing and loading from the Authenticator Storage
    """

    def __init__(self, key:RelyingPartyKey, username:str, password:str, empty=False):
        if empty:
            return
        self.rp_key = DICEKeyData(key.key_blob,username,password)
        self.rp_point = DICEKeyPoint(key.key_point)
        self.username = username
        self.password = password

    def as_json(self)->dict:
        """Generates a JSON compatible dictionary for storing

        Returns:
            dict: dictionary contain x and y
        """
        out = {}
        out["rp_key"] = self.rp_key.as_json()
        out["rp_point"] = self.rp_point.as_json()
        return out

    @classmethod
    def from_json(cls, load:dict)->'DICERelyingPartyKey':
        """Creates an instace from JSON

        Returns:
            DICERelyingPartyKey: new instance from JSON
        """

        new_rp_key = DICERelyingPartyKey(None,None,None,True)
        new_rp_key.rp_key = DICEKeyData.from_json(load["rp_key"])
        new_rp_key.rp_point = DICEKeyPoint.from_json(load["rp_point"])
        new_rp_key.username = new_rp_key.rp_key.username
        new_rp_key.password = new_rp_key.rp_key.password
        return new_rp_key

    def get_as_ec_public_key(self)->EllipticCurvePublicKey:
        """Gets the key as a python cryptography EllipticCurvePoint

        Returns:
            EllipticCurvePublicKey: Public key of the relying party
        """
        return EllipticCurvePublicNumbers(int(self.rp_point.x_point.hex(), 16),
            int(self.rp_point.y_point.hex(), 16),
            ec.SECP256R1()).public_key(default_backend())
    def get_as_relying_party_key_struct(self)->RelyingPartyKey:
        """Get this key as a RelyingPartyKey ctypes structure that
        can be passed to C

        Returns:
            RelyingPartyKey: ctypes structure to be passed to C
        """
        return RelyingPartyKey(self.rp_key.get_as_key_data_struct(),
            self.rp_point.get_as_key_ec_point_struct())

class DICEKeyData():
    """Represents a key pair with utility methods for encoding as
    a C structure and for storing and loading from Authenticator
    Storage
    """
    def __init__(self, key:KeyData,username:str, password:str, empty=False):
        if empty:
            return
        self.public_data = bytes(ctypes.string_at(key.public_data.data,
            ctypes.sizeof(ctypes.c_byte) * key.public_data.size))
        self.private_data = bytes(ctypes.string_at(key.private_data.data,
            ctypes.sizeof(ctypes.c_byte) * key.private_data.size))
        self.username = username
        self.password = password

    def as_json(self)->dict:
        """Generates a JSON compatible dictionary for storing

        Returns:
            dict: dictionary contain x and y
        """
        out = {}
        out["public_data"] = self.public_data.hex()
        out["private_data"] = self.private_data.hex()
        out["username"]=self.username
        out["password"]=self.password

        return out

    @classmethod
    def from_json(cls, load:dict)->'DICEKeyData':
        """Creates an instace from JSON

        Returns:
            DICEKeyData: new instance from JSON
        """
        new_key_data = DICEKeyData(None,None,None,empty=True)
        new_key_data.public_data = bytes.fromhex(load["public_data"])
        new_key_data.private_data = bytes.fromhex(load["private_data"])
        new_key_data.username = load["username"]
        new_key_data.password = load["password"]
        return new_key_data

    def get_as_key_data_struct(self)->KeyData:
        """Gets this key pair as a KeyData ctructure

        Returns:
            KeyData: ctypes structure to pass to C
        """
        ptr_pub = ctypes.cast(self.public_data, ctypes.POINTER(ctypes.c_byte))
        public_data_ba = ByteArray(len(self.public_data),ptr_pub)
        ptr_prv = ctypes.cast(self.private_data, ctypes.POINTER(ctypes.c_byte))
        private_data_ba = ByteArray(len(self.private_data),ptr_prv)
        return KeyData(public_data_ba,private_data_ba)



class TPMException(Exception):
    """Exception raised for errors with the TPM

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Incorrect transaction state"):
        self.message = message
        super().__init__(self.message)
class TPM():
    """A class for communicating with a TPM to perform the necessary crypto
    operations. The initialisation will check that paths are appropriately
    set and that the TPM can be communicated with.
    """
    LIB_PATH = "./tpm/lib/libwatpm.so"
    def __init__(self):
        """Initialises the TPM wrapper and loads the shared library.

        The caller must make an uninstall call once finished.

        Raises:
            TPMException: Raised if an exception occurs or validation fails
        """

        if not os.path.exists(TPM.LIB_PATH):
            raise TPMException("TPM Library cannot be found at: " + TPM.LIB_PATH)

        if not 'LD_LIBRARY_PATH' in os.environ or \
            os.environ['LD_LIBRARY_PATH'].find("/opt/ibmtss/utils")<0:
            raise TPMException("/opt/ibmtss/utils should be on the LD_LIBRARY_PATH")

        if not 'PATH' in os.environ or os.environ['PATH'].find("/opt/ibmtss/utils")<0:
            raise TPMException("/opt/ibmtss/utils should be on the PATH")

        try:
            self._tpm = ctypes.cdll.LoadLibrary(TPM.LIB_PATH)
        except Exception as exp:
            raise TPMException("Exception loading library") from exp


        self._tpm_ptr = None
        self.tpm_started=False
        #Configure functions
        #Install TPM
        self._tpm.install_tpm.restype = ctypes.c_void_p

        self._tpm.uninstall_tpm.argtypes = [ctypes.c_void_p]
        #Setup TPM
        self._tpm.setup_tpm.argtypes = [ctypes.c_void_p,ctypes.c_bool,
            ctypes.c_char_p,ctypes.c_char_p]
        self._tpm.setup_tpm.restype = ctypes.c_int

        #Get Last Error
        self._tpm.get_last_error.restype = ctypes.POINTER(ctypes.c_char)

        #create and load user key
        self._tpm.create_and_load_user_key.restype = KeyData
        self._tpm.create_and_load_user_key.argtypes = [ctypes.c_void_p,
            ByteArrayStr,ByteArrayStr]

        #Load user key
        self._tpm.load_user_key.restype = ctypes.c_int
        self._tpm.load_user_key.argtypes = [ctypes.c_void_p,KeyData,ByteArrayStr]

        #Create and load RP key
        self._tpm.create_and_load_rp_key.restype = RelyingPartyKey
        self._tpm.create_and_load_rp_key.argtypes = [ctypes.c_void_p,
            ByteArrayStr,ByteArrayStr,ByteArrayStr]

        #Load RP key
        self._tpm.load_rp_key.restype = KeyECCPoint
        self._tpm.load_rp_key.argtypes = [ctypes.c_void_p,KeyData,ByteArrayStr,ByteArrayStr]

        #Sign using RP Key
        self._tpm.sign_using_rp_key.restype = ECDSASig
        self._tpm.sign_using_rp_key.argtypes = [ctypes.c_void_p,
            ByteArrayStr,ByteArray,ByteArrayStr]

        #Flush data
        self._tpm.flush_data.restype = ctypes.c_int
        self._tpm.flush_data.argtypes = [ctypes.c_void_p]

        self._install()

    def _install(self):
        """Creates a new C instance of the TPM and returns the pointer
        """
        if not self._tpm_ptr is None:
            raise TPMException("Existing pointer to TPM, \
                cannot create second instance. Uninstall first")
        self._tpm_ptr = self._tpm.install_tpm()


    def uninstall(self):
        """Cleans up the C memory removing the TPM instance

        Will call Flush as a precaution beforehand

        Raises:
            TPMException: Raised if an error occurs flushing or
                deleting the instance
        """
        if self._tpm_ptr is None:
            raise TPMException("No TPM pointer set")
        self.flush()
        self._tpm.uninstall_tpm(self._tpm_ptr)
        self._tpm_ptr = None
        self.tpm_started = False



    def start_up_tpm(self, hw_tpm:bool=False, data_dir:str = "./data/tpm/",
        log_file:str="tpm_log"):
        """Starts up the TPM with appropriate paths set

        Args:
            hw_tpm (bool, optional): Set to False to use a similator,
                True for a real TPM. Defaults to False.
            data_dir (str, optional): path where data should be stored.
                Defaults to "./data/tpm/".
            log_file (str, optional): log file prefix. Defaults to "tpm_log".
        """

        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        self.tpm_started=True
        self._check_error(self._tpm.setup_tpm(
                self._tpm_ptr,hw_tpm,data_dir.encode(),log_file.encode()))


    def _check_error(self, response):
        """Utility method to check response from TPM call for any errors.

        If an error occurrs it will get the last error from the TPM and
        raise an exception

        Args:
            response (any): response from the TPM

        Raises:
            TPMException: Raised if a non-zero response is received from the TPM
        """
        if response != 0:
            self._check_started()
            error_string = self.get_last_error()
            raise TPMException("Error running TPM command: " + str(error_string))


    #def setup_tpm(self, simulator:bool,data_dir:str, log_file:str)->int:
    #    return self._tpm.setup_tpm(self._tpm_ptr,simulator,data_dir.encode(),log_file.encode())

    def _check_started(self):
        if not self.tpm_started:
            raise TPMException("TPM not started, you must call start_up_tpm first")

    def get_last_error(self)->str:
        """Gets the last error

        Returns:
            str: last error message from the TPM
        """
        buf=self._tpm.get_last_error(self._tpm_ptr)
        err=ctypes.cast(buf, ctypes.c_char_p).value
        return str(err)

    def create_and_load_user_key(self, username:str, pwd:str)->DICEKeyData:
        """Creates and loads a user key with the specified username and password

        This assumes that the TPM has been installed and setup prior to it being
        called.

        Args:
            username (str): username for the key
            pwd (str): password for the key

        Returns:
            DICEKeyData: Associated key data that should be stored locally
        """
        self._check_started()
        username_byte_array = ByteArrayStr(len(username),username.encode())
        password_byte_array = ByteArrayStr(len(pwd),pwd.encode())
        response_value = self._tpm.create_and_load_user_key(self._tpm_ptr, username_byte_array,
            password_byte_array)
        return DICEKeyData(response_value,username,pwd)

    def load_user_key(self, user_key:DICEKeyData):
        """Loads the specified TPM into the memory

        This assumes that the TPM has been installed and setup prior to it being
        called.

        Args:
            user_key (key_data): User key data


        """
        self._check_started()
        username_byte_array =  ByteArrayStr(len(user_key.username),user_key.username.encode())
        self._check_error(self._tpm.load_user_key(self._tpm_ptr,
            user_key.get_as_key_data_struct(), username_byte_array))


    def create_and_load_rp_key(self, relying_party:str,
            rp_key_auth:str,user_auth:str,)->DICERelyingPartyKey:
        """Creates and loads a Relying Party Key

        Args:
            relying_party (str): relying party name
            rp_key_auth (str): relying party password
            user_auth (str): user password

        Returns:
            DICERelyingPartyKey: [description]
        """
        self._check_started()
        relying_p = ByteArrayStr(len(relying_party),relying_party.encode())
        user_a = ByteArrayStr(len(user_auth),user_auth.encode())
        rp_key_a = ByteArrayStr(len(rp_key_auth),rp_key_auth.encode())
        return DICERelyingPartyKey(self._tpm.create_and_load_rp_key(self._tpm_ptr,
            relying_p,user_a,rp_key_a),relying_party,rp_key_auth)


    def load_rp_key(self, rp_key_data:DICERelyingPartyKey, user_password:str):
        """Loads the specified relying party key

        Args:
            rp_key_data (RelyingPartyKey): Relying party key data to load
            user_password (str): user password

        """
        self._check_started()
        user_password_byte_array = ByteArrayStr(len(user_password.encode()),user_password.encode())
        relying_party_byte_array = ByteArrayStr(len(rp_key_data.username.encode()),
            rp_key_data.username.encode())
        self._tpm.load_rp_key(self._tpm_ptr,
            rp_key_data.rp_key.get_as_key_data_struct(),
            relying_party_byte_array, user_password_byte_array)


    def sign_using_rp_key(self, relying_party:str, digest:bytes,
        rp_key_password:str)->DICEECDSASig:
        """Signs the specified digest that must be a SHA256 digest using the
        specified relying party and relying party password. The relying party's
        key must have been loaded prior to this call

        Args:
            relying_party (str): relying party name
            digest (bytes): digest to sign
            rp_key_password (str): relying party password

        Returns:
            DICEECDSASig: A DSA signature
        """
        self._check_started()
        relying_party_password = ByteArrayStr(len(rp_key_password),rp_key_password.encode())
        relying_party = ByteArrayStr(len(relying_party),relying_party.encode())
        ptr_digest = ctypes.cast(digest, ctypes.POINTER(ctypes.c_byte))
        digest_to_sign = ByteArray(len(digest),ptr_digest)
        return DICEECDSASig(self._tpm.sign_using_rp_key(self._tpm_ptr,relying_party,
            digest_to_sign, relying_party_password))


    def flush(self):
        """Flushes the TPM data

        """
        self._check_error(self._tpm.flush_data(self._tpm_ptr))
