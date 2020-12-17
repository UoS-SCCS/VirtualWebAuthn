
import ctypes
import os
import json


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (PrivateFormat,
    Encoding, NoEncryption)
from cryptography.hazmat.primitives.asymmetric.ec import (EllipticCurvePublicKey,
    EllipticCurvePublicNumbers, EllipticCurvePrivateKeyWithSerialization)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

"""
class KeyPair(ctypes.Structure):

    _fields_ = [('alg', ctypes.c_int),
                ('xpoint', ctypes.POINTER(ctypes.c_char)),
                ('ypount', ctypes.POINTER(ctypes.c_char))]

"""




#os.environ['PATH'] = "/opt/ibmtss/utils" + ';' + os.environ['PATH']
#os.environ['LD_LIBRARY_PATH'] = "/opt/ibmtss/utils" + ';' + os.environ['LD_LIBRARY_PATH']
#export LD_LIBRARY_PATH=/opt/ibmtss/utils
#export PATH=$PATH:/opt/ibmtss/utils
#tpm = ctypes.cdll.LoadLibrary("./libwatpm.so")
# Check connection worked
#print(vars(tpm))

#Set return type
#tpm.install_tpm.restype = ctypes.c_void_p

#Get TPM pointer
##tpm_ptr = tpm.install_tpm()
#tpm.setup_tpm.argtypes = [ctypes.c_void_p,ctypes.c_bool,ctypes.c_char_p,ctypes.c_char_p]


#const char* get_last_error(void* v_tpm_ptr);

#tpm.uninstall_tpm(tpm_ptr)

#print(mydll.myFunction())
#print(mydll.addFour(2))
#print(mydll.getKey())
class Byte_array(ctypes.Structure):

    _fields_ = [('size', ctypes.c_uint16),
                ('data', ctypes.POINTER(ctypes.c_byte))]

class Byte_array_str(ctypes.Structure):

    _fields_ = [('size', ctypes.c_uint16),
                ('data', ctypes.c_char_p)]

class Two_byte_arrays(ctypes.Structure):

    _fields_ = [('one', Byte_array),
                ('two', Byte_array)]


class key_data(ctypes.Structure):

    _fields_ = [('public_data', Byte_array),
                ('private_data', Byte_array)]

class key_ecc_point(ctypes.Structure):

    _fields_ = [('x_coord', Byte_array),
                ('y_coord', Byte_array)]

class relying_party_key(ctypes.Structure):

    _fields_ = [('key_blob', key_data),
                ('key_point', key_ecc_point)]

class ecdsa_sig(ctypes.Structure):

    _fields_ = [('sig_r', Byte_array),
                ('sig_s', Byte_array)]


class DiceECDSASig():
    def __init__(self, tpm_sig:ecdsa_sig):
        print(tpm_sig.sig_s.size)
        self.sig_r = bytes(ctypes.string_at(tpm_sig.sig_r.data, ctypes.sizeof(ctypes.c_byte) * tpm_sig.sig_r.size))
        self.sig_s = bytes(ctypes.string_at(tpm_sig.sig_s.data, ctypes.sizeof(ctypes.c_byte) * tpm_sig.sig_s.size))


    def get_as_ecdsa_struct(self)->key_data:
        ptr_r = ctypes.cast(self.sig_r, ctypes.POINTER(ctypes.c_byte))
        sig_r_ba = Byte_array(len(self.sig_r),ptr_r)
        ptr_s = ctypes.cast(self.sig_s, ctypes.POINTER(ctypes.c_byte))
        sig_s_ba = Byte_array(len(self.sig_s),ptr_s)
        return ecdsa_sig(sig_r_ba,sig_s_ba)

class DiceKeyPoint():
    def __init__(self, point:key_ecc_point):
        self.x = bytes(ctypes.string_at(point.x_coord.data, ctypes.sizeof(ctypes.c_byte) * point.x_coord.size))
        self.y = bytes(ctypes.string_at(point.y_coord.data, ctypes.sizeof(ctypes.c_byte) * point.y_coord.size))

    def get_as_key_ec_point_struct(self)->key_ecc_point:
        ptr_pub = ctypes.cast(self.x, ctypes.POINTER(ctypes.c_byte))
        x_data_ba = Byte_array(len(self.x),ptr_pub)
        ptr_prv = ctypes.cast(self.y, ctypes.POINTER(ctypes.c_byte))
        y_data_ba = Byte_array(len(self.y),ptr_prv)
        return key_ecc_point(x_data_ba,y_data_ba)

class DiceRelyingPartyKey():
    def __init__(self, key:relying_party_key):
        self.rp_key = DiceKeyData(key.key_blob)
        self.rp_point = DiceKeyPoint(key.key_point)

    def get_as_relying_party_key_struct(self)->relying_party_key:
        return relying_party_key(self.rp_key.get_as_key_data_struct(),self.rp_point.get_as_key_ec_point_struct())

class DiceKeyData():
    def __init__(self, key:key_data):
        self.public_data = bytes(ctypes.string_at(key.public_data.data, ctypes.sizeof(ctypes.c_byte) * key.public_data.size))
        self.private_data = bytes(ctypes.string_at(key.private_data.data, ctypes.sizeof(ctypes.c_byte) * key.private_data.size))


    def get_as_key_data_struct(self)->key_data:
        ptr_pub = ctypes.cast(self.public_data, ctypes.POINTER(ctypes.c_byte))
        public_data_ba = Byte_array(len(self.public_data),ptr_pub)
        ptr_prv = ctypes.cast(self.private_data, ctypes.POINTER(ctypes.c_byte))
        private_data_ba = Byte_array(len(self.private_data),ptr_prv)
        ####

        return key_data(public_data_ba,private_data_ba)
class TPM():
    def __init__(self):
        self._tpm = ctypes.cdll.LoadLibrary("./libwatpm.so")
        self._tpm_ptr = None
        self.user_key = None
        #Configure functions
        self._tpm.install_tpm.restype = ctypes.c_void_p
        self._tpm.setup_tpm.argtypes = [ctypes.c_void_p,ctypes.c_bool,ctypes.c_char_p,ctypes.c_char_p]
        self._tpm.setup_tpm.restype = ctypes.c_int
        self._tpm.get_last_error.restype = ctypes.POINTER(ctypes.c_char)
        self._tpm.get_byte_array.argtypes = [ctypes.c_void_p]
        self._tpm.get_byte_array.restype = Byte_array
        self._tpm.put_byte_array.argtypes = [ctypes.c_void_p,Byte_array]

        self._tpm.get_two_byte_arrays.argtypes = [ctypes.c_void_p]
        self._tpm.get_two_byte_arrays.restype = Two_byte_arrays
        self._tpm.put_two_byte_arrays.argtypes = [ctypes.c_void_p,Two_byte_arrays]

        self._tpm.create_and_load_user_key.restype = key_data
        self._tpm.create_and_load_user_key.argtypes = [ctypes.c_void_p,Byte_array_str,Byte_array_str]

        self._tpm.load_user_key.restype = ctypes.c_int
        self._tpm.load_user_key.argtypes = [ctypes.c_void_p,key_data,Byte_array_str]

        self._tpm.load_rp_key.restype = key_ecc_point
        self._tpm.load_rp_key.argtypes = [ctypes.c_void_p,key_data,Byte_array_str,Byte_array_str]

        self._tpm.create_and_load_rp_key.restype = relying_party_key
        self._tpm.create_and_load_rp_key.argtypes = [ctypes.c_void_p,Byte_array_str,Byte_array_str,Byte_array_str]

        self._tpm.sign_using_rp_key.restype = ecdsa_sig
        self._tpm.sign_using_rp_key.argtypes = [ctypes.c_void_p,Byte_array_str,Byte_array,Byte_array_str]

        self._tpm.flush_data.restype = ctypes.c_int
        self._tpm.flush_data.argtypes = [ctypes.c_void_p]
        self._install_tpm()

    def _install_tpm(self):
        self._tpm_ptr = self._tpm.install_tpm()

    def uninstall(self):
        if self._tpm_ptr is None:
            raise Exception("No TPM pointer set")
        self._tpm.uninstall_tpm(self._tpm_ptr)

    def setup_tpm(self, simulator:bool,data_dir:str, log_file:str)->int:
        return self._tpm.setup_tpm(self._tpm_ptr,simulator,data_dir.encode(),log_file.encode())

    def get_last_error(self):
        buf=self._tpm.get_last_error(self._tpm_ptr)
        err=ctypes.cast(buf, ctypes.c_char_p).value
        return err

    def create_and_load_user_key(self, username:str, pwd:str)->DiceKeyData:
        #NOTE: It is necessary to unmarshall and remarshall the data in order to send it back
        un = Byte_array_str(len(username),username.encode())
        pwd = Byte_array_str(len(pwd),pwd.encode())
        ret = self._tpm.create_and_load_user_key(self._tpm_ptr, un, pwd)
        return DiceKeyData(ret)
        #public_data = bytes(ctypes.string_at(ret.public_data.data, ctypes.sizeof(ctypes.c_byte) * ret.public_data.size))
        #private_data = bytes(ctypes.string_at(ret.private_data.data, ctypes.sizeof(ctypes.c_byte) * ret.private_data.size))
        #ptr = ctypes.cast(public_data, ctypes.POINTER(ctypes.c_byte))
        #public_data_ba = Byte_array(len(public_data),ptr)
        #ptr2 = ctypes.cast(private_data, ctypes.POINTER(ctypes.c_byte))
        #private_data_ba = Byte_array(len(private_data),ptr2)
        #return key_data(public_data_ba,private_data_ba)


    def load_user_key(self, user_key:key_data, username:str)->int:
        un = Byte_array_str(len(username),username.encode())
        return self._tpm.load_user_key(self._tpm_ptr,user_key, un)

    def create_and_load_rp_key(self, relying_party:str, user_auth:str, rp_key_auth:str):
        relying_p = Byte_array_str(len(relying_party),relying_party.encode())
        user_a = Byte_array_str(len(user_auth),user_auth.encode())
        rp_key_a = Byte_array_str(len(rp_key_auth),rp_key_auth.encode())
        return DiceRelyingPartyKey(self._tpm.create_and_load_rp_key(self._tpm_ptr,relying_p,user_a,rp_key_a))


    def load_rp_key(self, rp_key_data:relying_party_key, relying_party:str, user_password:str)->int:
        user_auth = Byte_array_str(len(user_password),user_password.encode())
        rp = Byte_array_str(len(relying_party),relying_party.encode())
        return self._tpm.load_rp_key(self._tpm_ptr,rp_key_data, rp, user_auth)


    def sign_using_rp_key(self, relying_party:str, data:bytes, rp_key_auth:str)->DiceECDSASig:
        rp_auth = Byte_array_str(len(rp_key_auth),rp_key_auth.encode())
        rp = Byte_array_str(len(relying_party),relying_party.encode())
        ptr_data = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte))
        data_to_sign = Byte_array(len(data),ptr_data)
        return DiceECDSASig(self._tpm.sign_using_rp_key(self._tpm_ptr,rp, data_to_sign, rp_auth))

    def encode_to_der(self, sig:DiceECDSASig)->bytes:
        marker = 48
        out = marker.to_bytes(1,"big")
        length = 4 + len(sig.sig_r) + len(sig.sig_s)
        out = out + length.to_bytes(1,"big")
        out = out + b'\x02'
        out = out + len(sig.sig_r).to_bytes(1,"big")
        out = out + sig.sig_r
        out = out + b'\x02'
        out = out + len(sig.sig_s).to_bytes(1,"big")
        out = out + sig.sig_s
        #alg = 46
        #out = out + alg.to_bytes(1,"big")
        #print(out.hex())
        return out

    def get_byte_array(self)->bytes:
        buf = self._tpm.get_byte_array(self._tpm_ptr)
        print("Size:" + str(buf.size))
        return bytes(ctypes.string_at(buf.data, ctypes.sizeof(ctypes.c_byte) * buf.size))

    def put_byte_array(self, data:bytes):
        ptr = ctypes.cast(data, ctypes.POINTER(ctypes.c_byte))
        my_byte_array = Byte_array(len(data),ptr)
        self._tpm.put_byte_array(self._tpm_ptr,my_byte_array)

    def get_two_byte_arrays(self)->{}:
        buf = self._tpm.get_two_byte_arrays(self._tpm_ptr)
        in_one=bytes(ctypes.string_at(buf.one.data, ctypes.sizeof(ctypes.c_byte) * buf.one.size))
        in_two=bytes(ctypes.string_at(buf.two.data, ctypes.sizeof(ctypes.c_byte) * buf.two.size))
        return {'one':in_one,'two':in_two}

    def put_two_byte_arrays(self, one:bytes, two:bytes):
        ptr_one = ctypes.cast(one, ctypes.POINTER(ctypes.c_byte))
        one_byte_array = Byte_array(len(one),ptr_one)
        ptr_two = ctypes.cast(two, ctypes.POINTER(ctypes.c_byte))
        two_byte_array = Byte_array(len(two),ptr_two)
        two_byte_arrays = Two_byte_arrays(one_byte_array,two_byte_array)
        self._tpm.put_two_byte_arrays(self._tpm_ptr,two_byte_arrays)
        tpm.put_byte_array(test)


    def flush(self)->int:
        return self._tpm.flush_data(self._tpm_ptr)

import binascii

def encode_sequence(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return "\x30".encode("latin-1") + encode_length(total_len) + "".encode("latin-1").join(encoded_pieces)

def encode_integer(r):
    assert r >= 0  # can't support negative numbers yet
    h = ("%x" % r).encode()
    if len(h) % 2:
        h = "0".encode("latin-1") + h
    s = binascii.unhexlify(h)
    num = str_idx_as_int(s, 0)
    if num <= 0x7F:
        return "\x02".encode("latin-1") + encode_length(len(s)) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return "\x02".encode("latin-1") + encode_length(len(s) + 1) + "\x00".encode("latin-1") + s



def str_idx_as_int(string, index):
    """Take index'th byte from string, return as integer"""
    val = string[index]
    if isinstance(val, int):
        return val
    return ord(val)

def encode_length(l):
    assert l >= 0
    if l < 0x80:
        return l.to_bytes(1,"big")
    s = ("%x" % l).encode()
    if len(s) % 2:
        s = "0".encode("latin-1") + s
    s = binascii.unhexlify(s)
    llen = len(s)
    return (0x80 | llen).to_bytes(1,"big") + s


tpm = TPM()


test = os.urandom(64)
test2 = os.urandom(64)
print(tpm.setup_tpm(False,"/home/dev/git/VirtualWebAuthN/Tpm_src/Ibmtss/Lib/test_data","log"))
#print(tpm.get_last_error())
tpm.put_byte_array(test)
check=tpm.get_byte_array()
if test == check:
    print("Success")
tpm.put_two_byte_arrays(test,test2)
res=tpm.get_two_byte_arrays()
if test == res['one'] and test2 == res['two']:
    print("Two arrays success")

kd=tpm.create_and_load_user_key("alfred","passwd")
print(kd.public_data)
print(tpm.load_user_key(kd.get_as_key_data_struct(),"alfred"))
rp_key=tpm.create_and_load_rp_key("webauthn.io","passwd","webauth")
tpm.load_rp_key(rp_key.rp_key.get_as_key_data_struct(),"webauthn.io","passwd")

msg = "This is a sig test".encode("UTF-8")
hash_alg = hashes.Hash(hashes.SHA256(),default_backend())
hash_alg.update(msg)
dig= hash_alg.finalize()

sig = tpm.sign_using_rp_key("webauthn.io",dig,"webauth")
print(tpm.get_last_error())
print(sig.sig_r)
print(len(sig.sig_r))
print(rp_key.rp_point.x.hex())
print(rp_key.rp_point.y.hex())
public_key = EllipticCurvePublicNumbers(int(rp_key.rp_point.x.hex(), 16),int(rp_key.rp_point.y.hex(), 16),
                ec.SECP256R1()).public_key(default_backend())
#print(encode_sequence(encode_integer(int(sig.sig_r.hex(),16)),encode_integer(int(sig.sig_s.hex(),16))).hex())
der_sig = tpm.encode_to_der(sig)
print(der_sig.hex())

print(tpm.flush())

kp = ec.generate_private_key(ec.SECP256R1,default_backend())
sig2 = kp.sign(msg,ec.ECDSA(hashes.SHA256()))

from cryptography.hazmat.primitives.asymmetric import utils
newsig = utils.encode_dss_signature(int(sig.sig_r.hex(), 16), int(sig.sig_s.hex(), 16))
print("SigTest")
print(public_key.verify(newsig ,msg,ec.ECDSA(hashes.SHA256())))
print(len(der_sig))
print("Alt")
print(len(sig2))
print(der_sig.hex())
print(sig2.hex())
print(sig2[len(sig2)-1])
#print(test)
#print(check)
#if test == check:
#    print("Success")
##print(tpm.put_two_byte_arrays(test,test2))
#res = tpm.get_two_byte_arrays()
#print(test)
#print(test2)
#print(res)

#if test == res['one'] and test2 == res['two']:
#    print("Two arrays success")

#do_something(test)
tpm.uninstall()

"""
export TPM_INTERFACE_TYPE=socsim
export LD_LIBRARY_PATH=/opt/ibmtss/utils
export PATH=$PATH:/opt/ibmtss/utils
"""