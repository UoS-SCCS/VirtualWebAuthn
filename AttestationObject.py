from PublicKeyCredentialSource import PublicKeyCredentialSource
from fido2 import cbor
class AttestationObject:

    @staticmethod
    def create_packed_self_attestation_object(credential_source:PublicKeyCredentialSource, authenticatorData:bytes, clientDataHash):
        statement = {}
        statement[2] = authenticatorData
        statement[1] = "packed"
        
        attStmt = {}
        attStmt["alg"] = credential_source.get_alg()
        #self attestation: concat (authenticatorData and clientDataHash) sign using private key
        attStmt["sig"] = credential_source.get_private_key().sign(authenticatorData + clientDataHash)
        statement[3] = attStmt
        print(statement)
        return statement
        
