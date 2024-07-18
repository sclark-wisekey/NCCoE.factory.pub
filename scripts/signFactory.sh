#!/bin/bash -e
#exit immediately if a command fails

# Sign a file using the VaultIC factory private key
# => Execute get_signature <filename>
# => Signature of <filename> bytes will be printed
# => Demonstration will sign the Makefile in the /build directory

# Execute the signature demonstration 
pushd ../VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/apps/sign/build
./get_signature Makefile

