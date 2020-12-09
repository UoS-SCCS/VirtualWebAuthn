from uuid import UUID
import logging
import json
from fido2 import cbor
from ctap.constants import AUTHN_GETINFO_VERSION, AUTHN_GETINFO_OPTION, AUTHN_GET_CLIENT_PIN_RESP, AUTHN_GETINFO, AUTHN_GETINFO_PARAMETER,AUTHN_GETINFO_PIN_UV_PROTOCOL, AUTHN_GETINFO_TRANSPORT
from authenticator.datatypes import PublicKeyCredentialParameters
log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')
class CBORResponse:
    def __init__(self):
        self.content = {}

    def __str__(self):
        out = {}
        out["type"] = str(type(self))
        out["content"]={}
        for key in self.content:
            if type(self.content[key])==bytes:
                auth.debug("Converting value to hex")
                out["content"][key]=self.content[key].hex()
        return json.dumps(out)

    def get_encoded(self):
        if len(self.content) == 0:
            return bytes(0)
        return cbor.encode(self.content)


class GetClientPINResp(CBORResponse):

    def __init__(self,key_agreement:{} = None, pin_token:bytes=None,retries:int=None):
        super(GetClientPINResp,self).__init__()
        self.content = {}
        if not key_agreement is None:
            self.content[AUTHN_GET_CLIENT_PIN_RESP.KEY_AGREEMENT.value] = key_agreement
            self.content[AUTHN_GET_CLIENT_PIN_RESP.KEY_AGREEMENT.value][3]=-25
        if not pin_token is None:
            self.content[AUTHN_GET_CLIENT_PIN_RESP.PIN_TOKEN.value] = pin_token
        if not retries is None:
            self.content[AUTHN_GET_CLIENT_PIN_RESP.RETRIES.value] = retries

class MakeCredentialResp(CBORResponse):

    def __init__(self,content):
        super(MakeCredentialResp,self).__init__()
        self.content = content

class GetAssertionResp(CBORResponse):

    def __init__(self,content, count):
        super(GetAssertionResp,self).__init__()
        self.content = content
        self.count=count

    def get_count(self)->int:
        return self.count
class GetNextAssertionResp(CBORResponse):

    def __init__(self,content, count:int):
        super(GetNextAssertionResp,self).__init__()
        self.content = content
        self.count = count

    def get_count(self)->int:
        return self.count

class ResetResp(CBORResponse):
    pass


class GetInfoResp(CBORResponse):

    def __init__(self, aaguid:bytes):
        super(GetInfoResp,self).__init__()
        self.set_check = {}
        # Default to internal AAGUID
        self.content[AUTHN_GETINFO.AAGUID.value] = aaguid
        #self.set_default_options()

    def set_default_options(self):
        self.set_option(AUTHN_GETINFO_OPTION.PLATFORM_DEVICE, False)
        self.set_option(AUTHN_GETINFO_OPTION.RESIDENT_KEY, False)
        self.set_option(AUTHN_GETINFO_OPTION.USER_PRESENCE, True)
        self.set_option(AUTHN_GETINFO_OPTION.USER_VERIFICATION_TOKEN, False)
        self.set_option(AUTHN_GETINFO_OPTION.CONFIG, False)

    def _add_to_dict(self, parameter: AUTHN_GETINFO, field: AUTHN_GETINFO_PARAMETER, value):
        if not parameter.value in self.content:
            self.content[parameter.value] = {}
        self.content[parameter.value][field.value]=value

    def _add_dict_to_list(self, parameter: AUTHN_GETINFO, value: dict):
        if not parameter.value in self.content:
            self.content[parameter.value] = []
        self.content[parameter.value].append(value)
        

    def _add_to_list(self, parameter: AUTHN_GETINFO, value: AUTHN_GETINFO_PARAMETER):
        if not parameter.value in self.content:
            self.content[parameter.value] = []
            self.set_check[parameter.value] = set()
        if not value.value in self.set_check[parameter.value]:
            self.content[parameter.value].append(value.value)
            self.set_check[parameter.value].add(value.value)
        else:
            raise Exception("Duplicate value in list or sequence")

    def add_version(self, version: AUTHN_GETINFO_VERSION):
        self._add_to_list(AUTHN_GETINFO.VERSIONS, version)

    def add_pin_uv_supported_protocol(self, protocol: AUTHN_GETINFO_PIN_UV_PROTOCOL):
        self._add_to_list(AUTHN_GETINFO.PIN_UV_AUTH_PROTOCOLS, protocol)

    def get(self, parameter: AUTHN_GETINFO):
        return self.content[parameter.value]

    def add_extension(self, extension):
        self._add_to_list(AUTHN_GETINFO.EXTENSIONS, extension)

    def set_auguid(self, aaguid: UUID):
        self.content[AUTHN_GETINFO.AAGUID.value] = aaguid.bytes

    def set_option(self, option: AUTHN_GETINFO_OPTION, value: bool):
        self._add_to_dict(AUTHN_GETINFO.OPTIONS, option, value)

    def set(self, parameter: AUTHN_GETINFO, value):
        self.content[parameter.value] = value

    def add_transport(self, transport: AUTHN_GETINFO_TRANSPORT):
        self._add_to_list(AUTHN_GETINFO.TRANSPORTS, transport)

    def add_algorithm(self, algorithm: PublicKeyCredentialParameters):
        self._add_dict_to_list(AUTHN_GETINFO.ALGORITHMS, algorithm)

        