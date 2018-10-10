# pfdtool

This is a modified version of flatz' pfdtool that provides a reusable library.

## Building pfdtool and library

### Crypto implementations

A few crypto implementation are provided, and pfdtool can be built with any combination from the table below.

| Name     | Value     | Algorithms    |
| -------- | --------- | ------------- |
| PolarSSL | polarssl  | AES, HMAC/SHA |
| mbed TLS | mbedtls   | AES, HMAC/SHA |
| Native   | native    | HMAC/SHA      |

Note: Native implementations are currently only supported on Windows.

### Building with CMake

```
mkdir build && cd build
cmake .. -DUSE_AES_IMPL=<AES implementation> -DUSE_SHA_IMPL=<HMAC/SHA implementation>
cmake --build .
```

### Creating Conan package

```
conan create . <reference> -o pfdtool:aes_impl=<AES implementation> -o pfdtool:sha_impl=<HMAC/SHA implementation>
```

## Licenses

| Name     | License                  | Usage                                     |
| -------- | ------------------------ | ----------------------------------------- |
| PolarSSL | GPL                      | Optional crypto implementations.          |
| mbed TLS | Apache 2.0               | Optional crypto implementations.          |
| getopt   | See license in getopt.c. | Required to build pfdtool CLI on Windows. |

## pfdtool 0.2.3

The original code of pfdtool is tagged as `0.2.3`, and can be built using Visual Studio 2010.
