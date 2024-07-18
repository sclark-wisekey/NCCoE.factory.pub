#!/bin/bash -e
#exit immediately if a command fails

# Go to /scripts folder
SCRIPT_DIR=$(dirname "$0")
pushd ${SCRIPT_DIR}

# The factory demonstration 
# => Generates Key Pair on VaultIC
# => Creates CSR
# => Sends CSR to INeS and retrieve the certificate
# => Writes the deviceFactoryCert.pem certificate to /certificates folder

# Build the factory demonstration
pushd ../VaultIC-TLS/demos/wolfssl/factory
rm -rf build
mkdir build
cd build
cmake ../
cmake --build .
ls
# return to /scripts folder
pushd ../../../../../scripts

# Provision the VaultIC
# => Read the certificate from the /certificates folder
# => Write the certificate to the VaultIC

# Build the provisioning demonstration
pushd ../VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/apps/perso_factory
rm -rf build
mkdir build
cd build
cmake ../
cmake --build .
# return to /apps folder
pushd ../../

# Read the certificate from the VaultIC
# => Read the certificate from VaultIC
# => Print the certificate bytes

# Build the read certificate from VaultIC demonstration
pushd read_cert
rm -rf build
mkdir build
cd build
cmake ../
cmake --build .
# return to /apps folder
pushd ../../

# Sign a file using the VaultIC factory private key
# => Execute get_signature <filename>

# Build the sign using VaultIC demonstration
pushd sign
rm -rf build
mkdir build
cd build
cmake ../
cmake --build .

