#
# CMakeLists.txt file for VaultIC Check TLS Perso app
#

cmake_minimum_required(VERSION 3.5)

set (NAME get_signature)
project(${NAME})

# Preprocessor Definitions
add_compile_definitions(TARGETCHIP_VAULTIC_405 USE_SPI WOLFSSL_USER_SETTINGS)

# Create Solution Folder for directories reference
set(SolutionDir ../../../../../)
include_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/include)

# Add the path to the static library
#link_directories(${SolutionDir}wolfssl/lib)
link_directories(${SolutionDir}VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/lib)

add_executable(${NAME} main.c)

#target_link_libraries(${NAME} vaultic_tls_405)
target_link_libraries(${NAME} vaultic_tls_408)

install(TARGETS ${NAME}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)






