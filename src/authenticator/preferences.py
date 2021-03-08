"""Contains class for reading and writing application preferences

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
from enum import Enum, unique

@unique
class PREFERENCE_KEY(Enum):
    """Key used in the JSON preference store

    """
    RK = "resident_key"
    AUTH_STORE = "auth_store"
class DICEPreferences():
    """ Manages application preferences
    """
    def __init__(self,path:str="./src/prefs.json"):
        self._path = path
        self._prefs = {}
        self._read_prefs()

    def _read_prefs(self):
        with open(self._path,"r") as file:
            self._prefs = json.load(file)

    def _write_prefs(self)->bool:
        try:
            with open(self._path,"w") as file:
                json.dump(self._prefs, file, indent = 4)
            return True
        except EnvironmentError:
            return False

    def _get_value(self, key:PREFERENCE_KEY, default=None):
        """Gets the value from prefs if it exists, or returns None

        Args:
            key (PREFERENCE_KEY): Key to get
            default : default value to return, Defaults to None

        Returns:
            (any): value of key if its exists or None
        """
        if key.value in self._prefs:
            return self._prefs[key.value]
        return default

    def get_resident_key(self)->bool:
        """Get whether to use a resident key

        Returns:
            bool: True to use a resident key, False otherwise, default is False
        """
        return self._get_value(PREFERENCE_KEY.RK,False)

    def set_resident_key(self, value:bool):
        """Sets whether to store key as resident keys

        Args:
            value (bool):True to store keys as resident, False if not
        """
        self._prefs[PREFERENCE_KEY.RK.value] = value
        self._write_prefs()

    def get_auth_store_path(self)->str:
        """Get the path where the storage file is

        Returns:
            str: Gets the str path to the storage file
        """
        return self._get_value(PREFERENCE_KEY.AUTH_STORE,False)

    def set_auth_store_path(self, value:str):
        """Sets the path to the auth store

        Args:
            value (str): file path to use for storing credentials
        """
        self._prefs[PREFERENCE_KEY.AUTH_STORE.value] = value
        self._write_prefs()
