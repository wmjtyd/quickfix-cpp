#include <iostream>
#include "rust/cxx.h"

#ifndef RUST_ENTRYPOINT_H
#define RUST_ENTRYPOINT_H

void create_client(rust::Fn<std::int32_t ()> func);

#endif
