
class AuthenticatorVersion:
    def __init__(self, ctaphid_protocol_version:int=2, major_version:int=1, minor_version:int=0, build_version:int=0):
        self.ctaphid_protocol_version=ctaphid_protocol_version
        self.major_version=major_version
        self.minor_version=minor_version
        self.build_version=build_version