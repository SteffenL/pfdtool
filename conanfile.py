from conans import ConanFile, CMake

class PfdtoolConan(ConanFile):
    name = "pfdtool"
    version = "0.2.3"
    url = "https://github.com/SteffenL/pfdtool"
    description = "A library made from flatz' pfdtool"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "aes_impl": ["polarssl", "mbedtls"],
        "sha_impl": ["polarssl", "mbedtls", "native"]
    }
    default_options = ("aes_impl=polarssl", "sha_impl=polarssl")
    generators = "cmake"
    exports_sources = "*"

    def build(self):
        cmake = CMake(self)
        cmake.definitions["USE_AES_IMPL"] = str(self.options.aes_impl)
        cmake.definitions["USE_SHA_IMPL"] = str(self.options.sha_impl)
        cmake.configure()
        cmake.build()

    def package(self):
        self.copy("*.h", dst="include", src="libpfdtool/include")

        self.copy("*.lib", dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so*", dst="lib", keep_path=False)
        self.copy("*.dylib*", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["libpfdtool"]
