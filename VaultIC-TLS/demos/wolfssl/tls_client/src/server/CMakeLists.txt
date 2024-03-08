cmake_minimum_required(VERSION 3.18)

set (EXE tls_server)
project(${EXE})

set(TLS_KIT_ROOT_FOLDER ../../../../../..)

# disable useless wolfssl options to speed up compiling
set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "" FORCE)
set(WOLFSSL_EXAMPLES "no" CACHE STRING "" FORCE)

add_subdirectory(${TLS_KIT_ROOT_FOLDER}/wolfssl wolfssl)
add_executable(${EXE} main.c)
target_link_libraries(${EXE} wolfssl)

file(COPY ${TLS_KIT_ROOT_FOLDER}/VaultIC-TLS/certificates/rootCACert.pem DESTINATION ./certs)
file(COPY ${TLS_KIT_ROOT_FOLDER}/VaultIC-TLS/certificates/serverCert.pem DESTINATION ./certs)
file(COPY ${TLS_KIT_ROOT_FOLDER}/VaultIC-TLS/certificates/serverKey.pem DESTINATION ./certs)