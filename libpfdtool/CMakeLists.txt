set(TARGET_NAME libpfdtool)

file(GLOB SOURCES src/*.c)

if(USE_AES_IMPL STREQUAL AES_IMPL_POLARSSL)
    list(APPEND SOURCES polarssl/polarssl/aes.c)
endif()

if(USE_SHA_IMPL STREQUAL SHA_IMPL_POLARSSL)
    list(APPEND SOURCES polarssl/polarssl/sha1.c)
endif()

if(USE_AES_IMPL STREQUAL AES_IMPL_MBEDTLS)
    list(APPEND SOURCES crypto_impl/crypto_mbedtls_aes.c mbedtls/mbedtls/aes.c)
endif()

if(USE_SHA_IMPL STREQUAL SHA_IMPL_MBEDTLS)
    list(APPEND SOURCES crypto_impl/crypto_mbedtls_sha.c
        mbedtls/mbedtls/md.c
        mbedtls/mbedtls/md_wrap.c
        mbedtls/mbedtls/platform_util.c
        mbedtls/mbedtls/sha1.c
    )
endif()

if(USE_SHA_IMPL STREQUAL SHA_IMPL_NATIVE)
    list(APPEND SOURCES crypto_impl/crypto_native_sha.c)
endif()

add_library(${TARGET_NAME} ${SOURCES})
target_include_directories(${TARGET_NAME} PUBLIC include)

if(MSVC)
    target_compile_definitions(${TARGET_NAME} PRIVATE _CRT_NONSTDC_NO_WARNINGS _CRT_SECURE_NO_WARNINGS)
endif()

if (USING_POLARSSL)
    target_include_directories(${TARGET_NAME} PRIVATE polarssl)
endif()

if (USING_MBEDTLS)
    target_include_directories(${TARGET_NAME} PRIVATE mbedtls)
endif()

if(USE_AES_IMPL STREQUAL AES_IMPL_POLARSSL)
    target_compile_definitions(${TARGET_NAME} PRIVATE CRYPT_AES_DEFAULT=CRYPT_AES_POLARSSL)
endif()

if(USE_SHA_IMPL STREQUAL SHA_IMPL_POLARSSL)
    target_compile_definitions(${TARGET_NAME} PRIVATE CRYPT_SHA_DEFAULT=CRYPT_SHA_POLARSSL)
endif()

if(USE_AES_IMPL STREQUAL AES_IMPL_MBEDTLS)
    target_compile_definitions(${TARGET_NAME} PRIVATE CRYPT_AES_DEFAULT=CRYPT_AES_MBEDTLS)
endif()

if(USE_SHA_IMPL STREQUAL SHA_IMPL_MBEDTLS)
    target_compile_definitions(${TARGET_NAME} PRIVATE CRYPT_SHA_DEFAULT=CRYPT_SHA_MBEDTLS)
endif()

if(USE_SHA_IMPL STREQUAL SHA_IMPL_NATIVE)
    target_compile_definitions(${TARGET_NAME} PRIVATE CRYPT_SHA_DEFAULT=CRYPT_SHA_NATIVE)
endif()
