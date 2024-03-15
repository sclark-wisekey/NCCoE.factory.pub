#!/bin/bash -e
#exit immediately if a command fails

devCertFile=./certs/deviceFactoryCert.der
caCertFile=./certs/rootCACert.der

./perso_factory $devKeyFile $devCertFile $caCertFile 
