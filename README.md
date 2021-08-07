# Virtual WebAuthn Authenticator
This repository contains the development of a Virtual CTAP2 WebAuthn authenticator. The authenticator is intended to provide a platform for testing and development of WebAuthn/CTAP2 protocols and extensions.

It provides code base for two kinds of authenticators. Firstly, a software only authenticator and secondly, a proof of concept implementation of a Trusted Platform Module (TPM) based authenticator, with associated interfaces and libraries for using a TPM as the underlying credential store. It is the first in a series of open source contributions that we will make in the area of WebAuthn authenticator platforms.

There is documentation within the code repository and an accompanying technical report on [Arxiv]().

The code was produced as part of the [EPSRC project](https://gow.epsrc.ukri.org/NGBOViewGrant.aspx?GrantRef=EP/N028295/1) that focused on Data to Improve the Customer Experience (DICE). The project's main application domain was intelligent transport systems (ITS) but the scope included ensuring security and data privacy when using web services, for example in the case of [smart ticketing](https://doi.org/10.1109/TDSC.2019.2940946) and [emerging technologies](https://doi.org/10.1007/978-3-030-64455-0_2) that could be applicable in the ITS domain.

Development Team:
* Chris Culnane,
* Chris Newton
* Helen Treharne

## Setup
Setup instructions for the TPM and the Virtual Authenticator are available as follows:
* [TPM Setup](./tpm/README.md)
* [Virtual Authenticator Setup](./SETUP.md)
