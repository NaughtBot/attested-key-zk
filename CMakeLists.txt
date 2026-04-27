cmake_minimum_required(VERSION 3.20)
project(attested_key_zk LANGUAGES CXX)

option(ATTESTED_KEY_ZK_BUILD_TESTS "Build native attested-key-zk tests" ON)
option(ATTESTED_KEY_ZK_SANITIZERS
       "Compile with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
set(ATTESTED_KEY_ZK_OPENSSL_ROOT "" CACHE PATH
    "Path prefix containing an OpenSSL install to link against")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_definitions(OPENSSL_SUPPRESS_DEPRECATED=1)

# Sanitizers are global so all linked code (including vendored longfellow-zk)
# is instrumented uniformly. Must be set before any add_library call.
if(ATTESTED_KEY_ZK_SANITIZERS)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

# First-party hardening — applied target-scoped so vendored longfellow-zk is
# spared the strict warning regime. Each candidate flag is probed at configure
# time so the same CMakeLists works across AppleClang / GCC / MSVC variants.
include(CheckCXXCompilerFlag)
set(_attested_key_zk_first_party_flags
    -Wall
    -Wextra
    -Werror
    -Wformat-security
    -fstack-protector-strong
    -fstack-clash-protection
    -fvisibility=hidden)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  list(APPEND _attested_key_zk_first_party_flags -fcf-protection=full)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
  list(APPEND _attested_key_zk_first_party_flags -mbranch-protection=standard)
endif()
set(ATTESTED_KEY_ZK_FIRST_PARTY_FLAGS "")
# Probe each flag with -Werror -Wunused-command-line-argument so clang's
# "argument unused" warnings (e.g. -fstack-clash-protection on Apple Clang)
# correctly classify a flag as unsupported, not just one we'll waste later.
set(_attested_key_zk_check_save_flags "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Werror -Wunused-command-line-argument")
foreach(_flag IN LISTS _attested_key_zk_first_party_flags)
  string(MAKE_C_IDENTIFIER "ATTESTED_KEY_ZK_HAS${_flag}" _flag_var)
  check_cxx_compiler_flag("${_flag}" ${_flag_var})
  if(${_flag_var})
    list(APPEND ATTESTED_KEY_ZK_FIRST_PARTY_FLAGS ${_flag})
  endif()
endforeach()
set(CMAKE_REQUIRED_FLAGS "${_attested_key_zk_check_save_flags}")

if(ATTESTED_KEY_ZK_OPENSSL_ROOT)
  set(ATTESTED_KEY_ZK_OPENSSL_INCLUDE_DIR
      "${ATTESTED_KEY_ZK_OPENSSL_ROOT}/include")
  set(ATTESTED_KEY_ZK_OPENSSL_CRYPTO_LIBRARY
      "${ATTESTED_KEY_ZK_OPENSSL_ROOT}/lib/libcrypto.a")
  if(NOT EXISTS "${ATTESTED_KEY_ZK_OPENSSL_INCLUDE_DIR}/openssl/crypto.h")
    message(FATAL_ERROR "Missing OpenSSL headers under ${ATTESTED_KEY_ZK_OPENSSL_INCLUDE_DIR}")
  endif()
  if(NOT EXISTS "${ATTESTED_KEY_ZK_OPENSSL_CRYPTO_LIBRARY}")
    message(FATAL_ERROR "Missing libcrypto.a under ${ATTESTED_KEY_ZK_OPENSSL_ROOT}/lib")
  endif()
  add_library(OpenSSL::Crypto STATIC IMPORTED)
  set_target_properties(OpenSSL::Crypto PROPERTIES
    IMPORTED_LOCATION "${ATTESTED_KEY_ZK_OPENSSL_CRYPTO_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${ATTESTED_KEY_ZK_OPENSSL_INCLUDE_DIR}"
  )
elseif(CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin" AND
       NOT CMAKE_SYSTEM_NAME STREQUAL "iOS" AND
       NOT CMAKE_SYSTEM_NAME STREQUAL "Android" AND
       EXISTS "/opt/homebrew/opt/openssl@3")
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  list(PREPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/openssl@3")
  set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
  find_package(OpenSSL REQUIRED COMPONENTS Crypto)
else()
  set(OPENSSL_USE_STATIC_LIBS TRUE)
  find_package(OpenSSL REQUIRED COMPONENTS Crypto)
endif()

get_target_property(ATTESTED_KEY_ZK_OPENSSL_INCLUDE_DIRS
  OpenSSL::Crypto INTERFACE_INCLUDE_DIRECTORIES)

set(LONGFELLOW_LIB_DIR
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/longfellow-zk/lib)

add_library(longfellow_core OBJECT
  ${LONGFELLOW_LIB_DIR}/util/log.cc
  ${LONGFELLOW_LIB_DIR}/util/crypto.cc
  ${LONGFELLOW_LIB_DIR}/algebra/nat.cc
  ${LONGFELLOW_LIB_DIR}/algebra/crt.cc
  ${LONGFELLOW_LIB_DIR}/ec/p256.cc
  ${LONGFELLOW_LIB_DIR}/circuits/sha/flatsha256_witness.cc
  ${LONGFELLOW_LIB_DIR}/circuits/sha/sha256_constants.cc
)
target_include_directories(longfellow_core
  PUBLIC
    ${LONGFELLOW_LIB_DIR}
  PRIVATE
    ${ATTESTED_KEY_ZK_OPENSSL_INCLUDE_DIRS}
)

add_library(attested_key_zk STATIC
  src/approval_proof_v1_zk.cc
  $<TARGET_OBJECTS:longfellow_core>
)
target_include_directories(attested_key_zk
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
# Vendored longfellow-zk headers are treated as SYSTEM so first-party warning
# flags (-Wall/-Wextra/-Werror) don't fire on them.
target_include_directories(attested_key_zk SYSTEM PRIVATE
    ${LONGFELLOW_LIB_DIR}
)
target_link_libraries(attested_key_zk PUBLIC OpenSSL::Crypto)
target_compile_options(attested_key_zk PRIVATE ${ATTESTED_KEY_ZK_FIRST_PARTY_FLAGS})
# _FORTIFY_SOURCE requires optimization and is a no-op (with a warning) under
# -O0; gate it on non-Debug configs so Debug builds aren't noisy.
target_compile_definitions(attested_key_zk PRIVATE
  $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>
  _GLIBCXX_ASSERTIONS)

if(ATTESTED_KEY_ZK_BUILD_TESTS)
  enable_testing()

  add_executable(approval_proof_v1_zk_test tests/approval_proof_v1_zk_test.cc)
  target_include_directories(approval_proof_v1_zk_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${ATTESTED_KEY_ZK_OPENSSL_INCLUDE_DIRS}
  )
  target_link_libraries(approval_proof_v1_zk_test PRIVATE attested_key_zk OpenSSL::Crypto)
  target_compile_options(approval_proof_v1_zk_test PRIVATE
    ${ATTESTED_KEY_ZK_FIRST_PARTY_FLAGS})
  add_test(NAME approval_proof_v1_zk_test COMMAND approval_proof_v1_zk_test)
endif()

install(TARGETS attested_key_zk DESTINATION lib)
install(FILES include/attested_key_zk/approval_proof_v1_zk.h
        DESTINATION include/attested_key_zk)
