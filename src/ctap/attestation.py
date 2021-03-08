"""Attestation packages

Contains constants, enums and classes for creating attestations

Classes:

 * :class:`AttestationStatement`
 * :class:`AttestationObject`

Enums:
    ATTESTATION
    ATTESTATION_STATEMENT
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
from enum import Enum, unique
from ctap.credential_source import PublicKeyCredentialSource


@unique
class ATTESTATION(Enum):
    """Attestion field enum

    """
    FMT = 1
    AUTH_DATA = 2
    ATT_STMT=3

@unique
class ATTESTATION_STATEMENT(Enum):
    """Attestation statement field enum

    """
    ALG = "alg"
    SIG = "sig"


class AttestationStatement:
    """AttestationStatement containing a CTAP2 attestation statement
    """
    def __init__(self, alg:int, sig:bytes):
        """Constructs an AttestationStatment

        Args:
            alg (int): COSE defined algorithm
            sig (bytes): statement signature as bytes
        """
        self.alg = alg
        self.sig=sig

    def get_statement(self)->dict:
        """Returns the statement as a dictionary with appropriate field names

        Returns:
            dict: Attestation statement with alg and sig
        """
        att_stmt = {}
        att_stmt[ATTESTATION_STATEMENT.ALG.value] = self.alg
        att_stmt[ATTESTATION_STATEMENT.SIG.value] = self.sig
        return att_stmt

class AttestationObject:
    """Attestation object that provides static utlity methods for
    creating various different attestation objects of different types
    or formats

    """
    @staticmethod
    def create_packed_self_attestation_object(credential_source:PublicKeyCredentialSource,
         authenticator_data:bytes, client_data_hash)->dict:
        """Creates a packed self attestation object

        Args:
            credential_source (PublicKeyCredentialSource): credential source being attested to
            authenticator_data (bytes): authenticator data
            client_data_hash ([type]): client data hash received in the request

        Returns:
            dict: dictiontary containing appropriate fields and values
        """
        statement = {}
        statement[ATTESTATION.FMT.value] = "packed"
        statement[ATTESTATION.AUTH_DATA.value] = authenticator_data
        att_stmt = AttestationStatement(credential_source.get_alg(),
            credential_source.get_private_key().sign(authenticator_data + client_data_hash))

        credential_source.increment_signature_counter()
        statement[ATTESTATION.ATT_STMT.value] = att_stmt.get_statement()
        return statement
