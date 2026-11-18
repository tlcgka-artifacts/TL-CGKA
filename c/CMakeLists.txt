cmake_minimum_required(VERSION 3.18)
project(tlcgka VERSION 2.2 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_library(SODIUM_LIBRARY NAMES sodium libsodium.so.23 REQUIRED)

add_library(tlcgka_objects OBJECT
    src/api.c
    src/crypto.c
    src/gua.c
    src/membership.c
    src/nonce_service.c
    src/tl.c
    src/ubkem.c
    src/value.c
)
set_target_properties(tlcgka_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(tlcgka_objects PRIVATE include src)
target_link_libraries(tlcgka_objects PRIVATE OpenSSL::Crypto)

add_library(tlcgka SHARED $<TARGET_OBJECTS:tlcgka_objects>)
target_include_directories(tlcgka PUBLIC include)
target_link_libraries(tlcgka PRIVATE OpenSSL::Crypto ${SODIUM_LIBRARY})

add_executable(tlcgka_cli src/main.c)
target_link_libraries(tlcgka_cli PRIVATE tlcgka)

include(CTest)
if(BUILD_TESTING)
    add_executable(tlcgka_tests tests/protocol_tests.c $<TARGET_OBJECTS:tlcgka_objects>)
    target_include_directories(tlcgka_tests PRIVATE include src)
    target_link_libraries(tlcgka_tests PRIVATE OpenSSL::Crypto ${SODIUM_LIBRARY})
    add_test(NAME protocol COMMAND tlcgka_tests)
    add_test(NAME group_update COMMAND tlcgka_cli demo 16 2 2 5)
    add_test(NAME core_membership COMMAND tlcgka_cli membership 16 2 2 3)
    add_test(NAME ordinary_membership COMMAND tlcgka_cli ordinary-membership 16 2 2 3)
endif()
