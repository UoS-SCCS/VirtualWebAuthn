Installing the IBM Software
=======================

Do all of following as root in your terminal, e.g., `sudo bash`.

TPM Simulator - currently ibmtpm1119
------------------------------------

```bash
mkdir /opt/ibmtpm1119
copy ibmtpm1119.tar.gz to /opt/ibmtpm1119

gunzip ibmtpm1119.tar.gz
tar -xvf ibmtpm1119.tar

cd src
make

cd /opt
ln -s ibmtpm1119 ibmtpm
```

### Note for 32 bit Linux

This will fail on 32 bit Linux because of a mismatch in `RADIX_BITS`
(assumed to be 64 for Linux). To fix this edit `Implementation.h` and
change `RADIX_BITS` to 32. Once changed re-run `make` and setup a
symlink as outlined above.

IBM TSS software stack - currently ibmtss1119
---------------------------------------------

```bash
mkdir /opt/ibmtss1119
mv ibmtss1119.tar.gz /opt/ibmtss1119

gunzip ibmtss1119.tar.gz
tar -xvf ibmtss1119.tar

cd utils

make

cd /opt
ln -s ibmtss1119 ibmtss
```

Once complete test the install by starting the simulator in a
terminal new window.

```bash
sudo /opt/ibmtpm/src/tpm_server
```

and then execute `/opt/ibmtss/utils/reg.sh -a` which runs all of the tests.

Setting file permissions
------------------------

Set access permissions to all files:

```bash
chmod 755 -R /opt/ibmt*
```

When this is complete you can now exit from the root shell.

Setting paths
-------------

To run the code without requiring root or sudo, set environment variables:

```bash
export LD_LIBRARY_PATH=/opt/ibmtss/utils
export PATH=$PATH:/opt/ibmtss/utils
```

If you are using a hardware TPM then set the following:

```bash
export TPM_INTERFACE_TYPE=dev
```

If not using a hardware TPM then set the simulator:

```bash
export TPM_INTERFACE_TYPE=socsim
```
