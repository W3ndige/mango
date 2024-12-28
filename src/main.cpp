#include "Yara.hpp"


int main() {
    Yara yara = Yara(0);
    
    yara.addSourceFromFile("../tests/files/test.yara");
    yara.initScanner();
    yara.scanFile("../tests/files/match_foo_test.txt");
}
