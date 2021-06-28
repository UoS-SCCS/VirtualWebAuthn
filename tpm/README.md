# Virtual WebAuthN TPM Interface
This folder contains the TPM interface code.


## Setup TPM
* Follow the instructions in [Installing_IBM_software](Installing_IBM_software.md) to create and start the IBM Simulator
* Once complete you should be able to run the simulator using `sudo /opt/ibmtpm/src/tpm_server`
    * use `sudo /opt/ibmtpm/src/tpm_server --rm` to reset the software TPM
* In this respository navigate to `./tpm/src` and then:
   1. Create a Build directory at the top level
   2. cd Build
   3. cmake ..
   4. make

* Once complete you should have a `./tpm/lib/libwatpm.so` file

### Setting Environment Variables
* Note: you will need to have set the environment variables in the terminal where you launch python from if it is different to the one you
used previously. Use the following to set them up.

    ```
    export LD_LIBRARY_PATH=/opt/ibmtss/utils
    export PATH=$PATH:/opt/ibmtss/utils
    export TPM_INTERFACE_TYPE=socsim
    ```
