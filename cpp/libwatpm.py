
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

class TPM():
    def __init__(self):
        self._tpm = ctypes.cdll.LoadLibrary("./libwatpm.so")
        self._tpm_ptr = None
        #Configure functions
        self._tpm.install_tpm.restype = ctypes.c_void_p
        self._tpm.setup_tpm.argtypes = [ctypes.c_void_p,ctypes.c_bool,ctypes.c_char_p,ctypes.c_char_p]
        self._tpm.get_last_error.restype = ctypes.POINTER(ctypes.c_char)
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

tpm = TPM()
print(tpm.setup_tpm(False,"./tpm_data/","tpm_debug.log"))
print(tpm.get_last_error())
tpm.uninstall()