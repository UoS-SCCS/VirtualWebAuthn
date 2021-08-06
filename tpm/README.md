# Virtual WebAuthN TPM Interface
This folder contains the TPM interface code.


## Setup TPM
* Follow the instructions in [Installing_IBM_software](Installing_IBM_software.md)
to install the IBM Simulator and the IBM TSS. In thecode it is assmumed that the
IBM TSS library is avaialable in `/opt/ibmtss/utils` and this is hard-wired in the
top level CMakeLists.txt file. If you install the TSS elsewhere create a soft
link to your install.
* Once complete you should be able to run the simulator using
`sudo /opt/ibmtpm/src/tpm_server` although to keep your files together
create a soft link to the tpm_server in one of your direcrtories and run it from
there.
    * use `tpm_server -rm` to reset the software TPM and start afresh with a new
storage root key.
* In this respository navigate to `./tpm/src` and then:
   1. Create a Build directory at the top level
   2. cd Build
   3. cmake ..
   4. make

* Once complete you should have a `./tpm/lib/libwatpm.so` file and a simple test
program `./tpm/src/Build/bin/test_wa_tpm`. This does a simple test of the TPM library.
To run the program, first start the TPM simulator and set the environment variables
as given below. Then run the program:
   * `bin/test_wa_tpm \<data directory\> \<log level (1, 2 or 3)\>`
The data directory is where the log file and any TPM temporary files will be stored.
The program displays some intermediate results and should end with:
    * `OpenSSL verified the ECDSA Signature`.
   
### Setting Environment Variables
* Note:  as described in [Installing_IBM_software](Installing_IBM_software.md) you
will need to have set the environment variables in the terminal where you launch
python from if it is different to the one you used previously. Use the following
to set them up.

    ```
    export LD_LIBRARY_PATH=/opt/ibmtss/utils
    export PATH=$PATH:/opt/ibmtss/utils
    export TPM_INTERFACE_TYPE=socsim
    ```
## The TPM library documentation
Documentation for the TPM library can be found in the `./tpm/docs` directory.
