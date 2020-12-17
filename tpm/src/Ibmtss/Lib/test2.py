
import ctypes
import os
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

class Two_byte_arrays(ctypes.Structure):

    _fields_ = [('one', Byte_array),
                ('two', Byte_array)]

class TPM():
    def __init__(self):
        self._tpm = ctypes.cdll.LoadLibrary("./libwatpm.so")
        self._tpm_ptr = None
        #Configure functions
        self._tpm.install_tpm.restype = ctypes.c_void_p
        self._tpm.setup_tpm.argtypes = [ctypes.c_void_p,ctypes.c_bool,ctypes.c_char_p,ctypes.c_char_p]
        self._tpm.get_last_error.restype = ctypes.POINTER(ctypes.c_char)
        self._tpm.get_byte_array.argtypes = [ctypes.c_void_p]
        self._tpm.get_byte_array.restype = Byte_array
        self._tpm.put_byte_array.argtypes = [ctypes.c_void_p,Byte_array]

        self._tpm.get_two_byte_arrays.argtypes = [ctypes.c_void_p]
        self._tpm.get_two_byte_arrays.restype = Two_byte_arrays
        self._tpm.put_two_byte_arrays.argtypes = [ctypes.c_void_p,Two_byte_arrays]

        self._install_tpm()

    def _install_tpm(self):
        self._tpm_ptr = self._tpm.install_tpm()

    def uninstall(self):
        if self._tpm_ptr is None:
            raise Exception("No TPM pointer set")
        self._tpm.uninstall_tpm(self._tpm_ptr)

    def setup_tpm(self, simulator:bool,data_dir:str, log_file:str)->int:
        return self._tpm.setup_tpm(self._tpm_ptr,simulator,ctypes.create_string_buffer(data_dir.encode()),ctypes.create_string_buffer(log_file.encode()))

    def get_last_error(self):
        buf=self._tpm.get_last_error(self._tpm_ptr)
        err=ctypes.cast(buf, ctypes.c_char_p).value
        return err

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
        self.two_byte_arrays = Two_byte_arrays(one_byte_array,two_byte_array)
        self._tpm.put_two_byte_arrays(self._tpm_ptr,self.two_byte_arrays)



tpm = TPM()
test = os.urandom(4)
test2 = os.urandom(4)

#print(tpm.setup_tpm(False,"./tpm_data/","tpm_debug.log"))
print(tpm.get_last_error())

#print(test)
#print(check)
#if test == check:
#    print("Success")
#print(tpm.put_two_byte_arrays(test,test2))
#res = tpm.get_two_byte_arrays()
#print(test)
#print(test2)
#print(res)
tpm.put_byte_array(test)
#if test == res['one'] and test2 == res['two']:
#    print("Two arrays success")

#do_something(test)
#tpm.uninstall()

"""
export TPM_INTERFACE_TYPE=socsim
export LD_LIBRARY_PATH=/opt/ibmtss/utils
export PATH=$PATH:/opt/ibmtss/utils
"""