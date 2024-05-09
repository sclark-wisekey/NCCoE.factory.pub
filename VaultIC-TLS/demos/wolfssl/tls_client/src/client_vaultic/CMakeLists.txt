#
# CMakeLists.txt file for VaultIC TLS client app
#

cmake_minimum_required(VERSION 3.5)

# Define the project name
set (NAME client_vaultic)
project(${NAME})

# Preprocessor Definitions
add_compile_definitions(TARGETCHIP_VAULTIC_405 USE_SPI WOLFSSL_USER_SETTINGS)

# Create Solution Folder for directories reference
set(SolutionDir ../../../../../../)
include_directories(${SolutionDir}VaultIC-TLS/demos/wolfssl/factory/include)
include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/include)
include_directories(${SolutionDir}wolfssl)
include_directories(${SolutionDir}wolfssl/wolfcrypt)

# Add the path to the static library
#link_directories(${SolutionDir}wolfssl/lib)
link_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/lib)
link_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/lib/so)


add_executable(${NAME} main.c)

# vaultic_tls_crypto vaultic_tls_405
target_link_libraries(${NAME} wolfssl vaultic_tls_405 vaultic_wolfssl)


install(TARGETS ${NAME}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

