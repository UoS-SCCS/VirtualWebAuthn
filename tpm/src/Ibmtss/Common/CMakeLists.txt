cmake_minimum_required(VERSION 3.13)

target_sources(watpm
    PRIVATE
        Create_ecdsa_key.cpp
        Create_primary_rsa_key.cpp
        Create_storage_key.cpp
        Ecdsa_sign.cpp
        Flush_context.cpp
        Load_key.cpp
        Make_key_persistent.cpp
        Marshal_data.cpp
        Tpm_error.cpp
        Tpm_initialisation.cpp
        Tpm_utils.cpp
        Tss_setup.cpp
        Web_authn_access_tpm.cpp
        Web_authn_tpm.cpp
)

