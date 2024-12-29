#include "Yara.hpp"

#include <CLI11.hpp>

int main(int argc, char *argv[]) {

    CLI::App app{"YaraX scanner"};

    std::string yara_source;
    app.add_option("-y, --yara", yara_source, "Path to YaraX rule.")->required();

    std::string target;
    app.add_option("-t, --target", target, "Path to the file to scan.")->required();

    CLI11_PARSE(app, argc, argv);

    Yara yara = Yara(0);
    
    yara.addSourceFromFile(yara_source.c_str());
    yara.initScanner();
    yara.scanFile(target.c_str());
}
