#include "Entrypoint.h"

void create_client(rust::Fn<std::int32_t ()> func) {
    int response = func();
    std::cout << response << std::endl;
}
