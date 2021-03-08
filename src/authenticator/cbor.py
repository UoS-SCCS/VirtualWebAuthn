"""Contains CBOR messaging classes
Classes:

 * :class:`CBORResponse`
 * :class:`GetClientPINResp`
 * :class:`MakeCredentialResp`
 * :class:`GetAssertionResp`
 * :class:`GetNextAssertionResp`
 * :class:`ResetResp`
 * :class:`GetInfoResp`
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

from abc import ABC
from uuid import UUID
import logging
import json
from fido2 import cbor
from ctap.constants import (AUTHN_GETINFO_VERSION, AUTHN_GETINFO_OPTION,
    AUTHN_GET_CLIENT_PIN_RESP, AUTHN_GETINFO, AUTHN_GETINFO_PARAMETER,
    AUTHN_GETINFO_PIN_UV_PROTOCOL, AUTHN_GETINFO_TRANSPORT)
from authenticator.datatypes import PublicKeyCredentialParameters
log = logging.getLogger('debug')
auth = logging.getLogger('debug.auth')

class CBORResponse(ABC):
    """General CBORResponse class that acts as the base for all
    CBOR response. Provides methods for encoding and logging the
    contents of the CBOR Response

    This class acts as a super class to the other responses
    providing the generic encoding method
    """
    def __init__(self):
        self.content = {}

    def __str__(self):
        """Generates a string representation of the CBORResponse
        as a JSON string

        Returns:
            str: JSON String representing CBOR Response
        """
        out = {}
        out["type"] = str(type(self))
        out["content"]={}
        for key in self.content:
            if isinstance(self.content[key], bytes):
                auth.debug("Converting value to hex")
                out["content"][key]=self.content[key].hex()
        return json.dumps(out)

    def get_encoded(self)->bytes:
        """Encodes the response as a CBOR object and returns
        the bytes.

        Returns:
            bytes: CBOR encoded version of response contents
        """
        if len(self.content) == 0:
            return bytes(0)
        return cbor.encode(self.content)


class GetClientPINResp(CBORResponse):
    """Get Client PIN response object
    """
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
    """MakeCredential response object
    """
    def __init__(self,content):
        super(MakeCredentialResp,self).__init__()
        self.content = content

class GetAssertionResp(CBORResponse):
    """GetAssertion Response
    """
    def __init__(self,content, count):
        super(GetAssertionResp,self).__init__()
        self.content = content
        self.count=count

    def get_count(self)->int:
        """Gets the count of credentials

        Returns:
            int: number of credentials found
        """
        return self.count
class GetNextAssertionResp(CBORResponse):
    """Get Next Assertion response
    """
    def __init__(self,content, count:int):
        super(GetNextAssertionResp,self).__init__()
        self.content = content
        self.count = count

    def get_count(self)->int:
        """Gets the count of credentials

        Returns:
            int: number of credentials found
        """
        return self.count

class ResetResp(CBORResponse):
    """Reset Response

    """



class GetInfoResp(CBORResponse):
    """GetInfo Response

    Constructs the response object based on the capabilities of
    the authenticator

    """
    def __init__(self, aaguid:bytes):
        super(GetInfoResp,self).__init__()
        self.set_check = {}
        # Default to internal AAGUID
        self.content[AUTHN_GETINFO.AAGUID.value] = aaguid
        #self.set_default_options()

    def set_default_options(self):
        """Sets default options for GetInfo
        """
        self.set_option(AUTHN_GETINFO_OPTION.PLATFORM_DEVICE, False)
        self.set_option(AUTHN_GETINFO_OPTION.RESIDENT_KEY, False)
        self.set_option(AUTHN_GETINFO_OPTION.USER_PRESENCE, True)
        self.set_option(AUTHN_GETINFO_OPTION.USER_VERIFICATION_TOKEN, False)
        self.set_option(AUTHN_GETINFO_OPTION.CONFIG, False)

    def _add_to_dict(self, parameter: AUTHN_GETINFO, field: AUTHN_GETINFO_PARAMETER, value):
        """Add a paremeter value to the dictionary

        Args:
            parameter (AUTHN_GETINFO): parameter within GetInfo to set
            field (AUTHN_GETINFO_PARAMETER): field to set
            value ([type]): value to set
        """
        if not parameter.value in self.content:
            self.content[parameter.value] = {}
        self.content[parameter.value][field.value]=value

    def _add_dict_to_list(self, parameter: AUTHN_GETINFO, value: dict):
        """For list parameters create or add the passed dictionary to the list

        Args:
            parameter (AUTHN_GETINFO): parameter that should be a list to add to
            value (dict): dictionary to add to the list
        """
        if not parameter.value in self.content:
            self.content[parameter.value] = []
        self.content[parameter.value].append(value)

    def _add_to_list(self, parameter: AUTHN_GETINFO, value: AUTHN_GETINFO_PARAMETER):
        """adds a value to a parameter that is supposed to a list of values

        Args:
            parameter (AUTHN_GETINFO): parameter that represents a list of values
            value (AUTHN_GETINFO_PARAMETER): value to add to the list

        Raises:
            Exception: raised if an attempt is made to add duplicate values, which would
                result in a non-compliant list
        """
        if not parameter.value in self.content:
            self.content[parameter.value] = []
            self.set_check[parameter.value] = set()
        if not value.value in self.set_check[parameter.value]:
            self.content[parameter.value].append(value.value)
            self.set_check[parameter.value].add(value.value)
        else:
            raise Exception("Duplicate value in list or sequence")

    def add_version(self, version: AUTHN_GETINFO_VERSION):
        """Add the version to the parameters

        Args:
            version (AUTHN_GETINFO_VERSION): version
        """
        self._add_to_list(AUTHN_GETINFO.VERSIONS, version)

    def add_pin_uv_supported_protocol(self, protocol: AUTHN_GETINFO_PIN_UV_PROTOCOL):
        """Sets the PIN User Verification protocol that is supported

        Args:
            protocol (AUTHN_GETINFO_PIN_UV_PROTOCOL): protocol version supported
        """
        self._add_to_list(AUTHN_GETINFO.PIN_UV_AUTH_PROTOCOLS, protocol)

    def get(self, parameter: AUTHN_GETINFO):
        """Gets a parameter from the GetInfo dictionary

        Args:
            parameter (AUTHN_GETINFO): parameter to get

        Returns:
            : value of parameter
        """
        return self.content[parameter.value]

    def add_extension(self, extension):
        """Add an extension to the extensions list

        Args:
            extension ([type]): extension to add
        """
        self._add_to_list(AUTHN_GETINFO.EXTENSIONS, extension)

    def set_auguid(self, aaguid: UUID):
        """Sets the AA GUID

        Args:
            aaguid (UUID): AAGUID for authenticator
        """
        self.content[AUTHN_GETINFO.AAGUID.value] = aaguid.bytes

    def set_option(self, option: AUTHN_GETINFO_OPTION, value: bool):
        """Sets one of the option values

        Args:
            option (AUTHN_GETINFO_OPTION): option to set
            value (bool): value
        """
        self._add_to_dict(AUTHN_GETINFO.OPTIONS, option, value)

    def set(self, parameter: AUTHN_GETINFO, value):
        """Sets a generic parameter

        Args:
            parameter (AUTHN_GETINFO): parameter to set
            value ([type]): value to set, could string, dictionary, etc.
        """
        self.content[parameter.value] = value

    def add_transport(self, transport: AUTHN_GETINFO_TRANSPORT):
        """Add a transport parameter

        Args:
            transport (AUTHN_GETINFO_TRANSPORT): supported transport to add
        """
        self._add_to_list(AUTHN_GETINFO.TRANSPORTS, transport)

    def add_algorithm(self, algorithm: PublicKeyCredentialParameters):
        """Adds a supported algorithm

        Args:
            algorithm (PublicKeyCredentialParameters): algorithm descriptor to add
        """
        self._add_dict_to_list(AUTHN_GETINFO.ALGORITHMS, algorithm)
