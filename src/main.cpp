#include "Scanner.hpp"

int main(int argc, char *argv[]) {
    Scanner scanner = Scanner();
    scanner.parseArguments(argc, argv);
    scanner.scan();
}
