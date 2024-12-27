#include "Yara.hpp"


int main() {
    Yara yara = Yara(0);
    
    yara.add_source_from_file("../yara/test.yara");
    yara.init_scanner();
    yara.scan_file("../tests/foo_test.txt");
}
