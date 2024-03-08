# We want a "recent" cmake to use the latest features
cmake_minimum_required(VERSION 3.6)

#Project name
project(factory VERSION 1.0.0)

# Preprocessor Definitions
add_compile_definitions(TARGETCHIP_VAULTIC_405 USE_SPI WOLFSSL_USER_SETTINGS)

# Include local libraries in the CMake process
add_subdirectory(lib/ini)
add_subdirectory(lib/json)
add_subdirectory(vaultic)

# Create Solution Folder for directories reference
set(SolutionDir ../../../../)

# Add Path to Header Files
include_directories(include)
include_directories(vaultic)
include_directories(${SolutionDir}wolfssl)
include_directories(${SolutionDir}wolfssl/wolfcrypt)
include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/device/vaultic_4XX_family)
include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_elib_405/src/common)

#LINK_DIRECTORIES(lib)

#source files directory
set(SRCS 
    "src/wisekey_Http_Request_Manager.c"
    "src/wisekey_Crypto_Tools.c"
    "src/wisekey_Tools.c"
    "src/wisekey_Ines_Agent.c"
    "src/main.c"    
    )

set(HEADERS
    "include/wisekey_ZTP_settings.h"
    "include/wisekey_Http_Request_Manager.h"
    "include/wisekey_Crypto_Tools.h"
    "include/wisekey_Tools.h"
    "include/wisekey_Ines_Agent.h"
)

INCLUDE_DIRECTORIES(include)

# Add the path to the static library
link_directories(${SolutionDir}wolfssl/lib)
link_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/lib)




set(ALL_FILES ${Source_Files})
add_executable(${PROJECT_NAME} ${SRCS} ${HEADERS})

target_link_libraries(${PROJECT_NAME} ini json vaultic )
target_link_libraries(${PROJECT_NAME} libwolfssl.a m)
target_link_libraries(${PROJECT_NAME} libvaultic_tls_405.a libvaultic_tls_crypto.a)
