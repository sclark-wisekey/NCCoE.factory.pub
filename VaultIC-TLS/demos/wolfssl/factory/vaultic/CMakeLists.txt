# We want a "recent" cmake to use the latest features
cmake_minimum_required(VERSION 3.6)

# Name of the project is vaultic
project(vaultic)

# Preprocessor Definitions
add_compile_definitions(TARGETCHIP_VAULTIC_405 USE_SPI)


# Create Solution Folder for directories reference
set(SolutionDir ../../../../../)
set(IncludeDir ../../../../../)
#set(IncludeDir ../../../../../VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/include/)
#set(IncludeDir ../../../../../VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/include/

# We don't need to compile the vaultic library since it is added as a static library
#add_subdirectory(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/src vaultic_tls)

# Define all of the directories that contain headers to include
include_directories(${SolutionDir}VaultIC-TLS/demos/wolfssl/factory/include)
include_directories(${SolutionDir}VaultIC-TLS/demos/wolfssl/factory/lib/ini)
include_directories(${SolutionDir}VaultIC-TLS/demos/wolfssl/factory/vaultic)
include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/include/)

#include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/common)
#include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/crypto)
#include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/device/vaultic_4XX_family)
#include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/device/vaultic_4XX_family/crypto)
#include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/device/vaultic_4XX_family/auth)
#include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/device/vaultic_4XX_family/vaultic_405)
#include_directories(${SolutionDir}wolfssl)

# Create variables with the files to be compiled
set(SRCS
    vaultic_csr.c
    vaultic_factory.c
    )
    
set(HEADERS
    vaultic_csr.h
    ${IncludeDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/include/vaultic_common.h
    )
source_group( include FILES ${HEADERS} )
source_group( src FILES ${SRCS} )
    
add_library(vaultic ${SRCS} ${HEADERS})
