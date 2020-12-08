from PublicKeyCredentialSource import PublicKeyCredentialSource
from fido2 import cbor
from enum import Enum, unique

@unique
class ATTESTATION(Enum):
    FMT = 1
    AUTH_DATA = 2
    ATT_STMT=3

@unique
class ATTESTATION_STATEMENT(Enum):
    ALG = "alg"
    SIG = "sig"
    

class AttestationStatement:
    def __init__(self, alg:int, sig:bytes):
        self.alg = alg
        self.sig=sig
    
    def get_statement(self)->{}:
        attStmt = {}
        attStmt[ATTESTATION_STATEMENT.ALG.value] = self.alg
        #self attestation: concat (authenticatorData and clientDataHash) sign using private key
        attStmt[ATTESTATION_STATEMENT.SIG.value] = self.sig
        return attStmt
        
class AttestationObject:

    @staticmethod
    def create_packed_self_attestation_object(credential_source:PublicKeyCredentialSource, authenticatorData:bytes, clientDataHash):
        statement = {}
        statement[ATTESTATION.FMT.value] = "packed"
        statement[ATTESTATION.AUTH_DATA.value] = authenticatorData
        #self attestation: concat (authenticatorData and clientDataHash) sign using private key
        attStmt = AttestationStatement(credential_source.get_alg(),credential_source.get_private_key().sign(authenticatorData + clientDataHash))
        #attStmt = {}
        #attStmt["alg"] = credential_source.get_alg()
        
        #attStmt["sig"] = credential_source.get_private_key().sign(authenticatorData + clientDataHash)
        credential_source.increment_signature_counter()
        statement[ATTESTATION.ATT_STMT.value] = attStmt.get_statement()
        return statement
        
