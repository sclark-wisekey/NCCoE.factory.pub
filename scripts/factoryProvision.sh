#!/bin/bash -e
#exit immediately if a command fails

# The factory demonstration 
# => Generates Key Pair on VaultIC
# => Creates CSR
# => Sends CSR to INeS and retrieve the certificate
# => Writes the deviceFactoryCert.pem certificate to /certificates folder

# Build the factory demonstration
pushd ../VaultIC-TLS/demos/wolfssl/factory/build
./factory

# Convert the PEM to DER in the /certificates folder
pushd ../../../../certificates
openssl x509 -in deviceFactoryCert.pem -out deviceFactoryCert.der -outform DER

# Write the DER certificate to the VaultIC with the perso_factory app
pushd ../vaultic_tls/vaultic_tls-4xx/apps/perso_factory/build
chmod +rwx *.sh
./perso_client.sh

