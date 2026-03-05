#ifndef TRECDSA_ERRORS_H
#define TRECDSA_ERRORS_H

#include <stdexcept>

namespace trecdsa {

class ProtocolError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

}

#endif
