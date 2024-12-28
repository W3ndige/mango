#include "Yara.hpp"


int main() {
    Yara yara = Yara(0);
    
    yara.add_source_from_file("../tests/files/test.yara");
    yara.init_scanner();
    yara.scan_file("../tests/files/match_foo_test.txt");
}
