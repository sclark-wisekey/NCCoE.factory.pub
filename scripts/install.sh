#!/bin/bash -e
#exit immediately if a command fails

# Install CMake
sudo apt update
sudo apt full-upgrade
sudo apt install cmake -y
cmake --version
