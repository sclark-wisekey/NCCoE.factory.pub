#!/bin/bash -e
#exit immediately if a command fails

# Go to scripts folder
SCRIPT_DIR=$(dirname "$0")
pushd ${SCRIPT_DIR}

# Run wolfssl server 

echo Running wolfssl tls server ...
pushd ../build_server
./tls_server
popd

# Return to initial folder
popd
echo -e "\n"
