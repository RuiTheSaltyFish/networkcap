#include <iostream>
#include <exception>


class NetworkCardNotFoundException : public std::exception {
public:
    const char* what() const noexcept override {
        return "Network Card Not Found";
    }
};