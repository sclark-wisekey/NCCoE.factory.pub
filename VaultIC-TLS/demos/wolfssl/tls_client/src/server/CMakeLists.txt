#
# CMakeLists.txt file for VaultIC TLS server demo app
#

cmake_minimum_required(VERSION 3.5)

# Define the project name
set (NAME tls_server)
project(${NAME})

# Create Solution Folder for directories reference
set(SolutionDir ../../../../../../)
#include_directories(${SolutionDir}VaultIC-TLS/demos/wolfssl/factory/include)
include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/include)
include_directories(${SolutionDir}wolfssl)
include_directories(${SolutionDir}wolfssl/wolfcrypt)

# Add the path to the static library
#link_directories(${SolutionDir}wolfssl/lib)
link_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/lib)
link_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/lib/so)

# disable useless wolfssl options to speed up compiling
set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "" FORCE)
set(WOLFSSL_EXAMPLES "no" CACHE STRING "" FORCE)

add_executable(${NAME} main.c)

# vaultic_tls_crypto vaultic_tls_405
target_link_libraries(${NAME} wolfssl )

# Copy the certificates and keys to be used 
file(COPY ${SolutionDir}/VaultIC-TLS/certificates/rootCACert.pem DESTINATION ./certs)
file(COPY ${SolutionDir}/VaultIC-TLS/certificates/serverCert.pem DESTINATION ./certs)
file(COPY ${SolutionDir}/VaultIC-TLS/certificates/serverKey.pem DESTINATION ./certs)

# Set the permissions
install(TARGETS ${NAME}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
