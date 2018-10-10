#include <pfdtool/util.h>
#include <iostream>

int main() {
    if (x_to_u64("11223344") != 0x11223344) {
        return 1;
    }

    std::cout << "pfdtool works!" << std::endl;
    return 0;
}
