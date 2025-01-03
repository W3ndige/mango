#include "Yara.hpp"

#include <filesystem>
#include <CLI/CLI.hpp>



void start_scanning(std::string source, std::string target, bool dumpMatches, bool recurse, bool verbose) {
    std::filesystem::path source_path = source;
    std::filesystem::path target_path = target;
    
    Yara yara = Yara(0, dumpMatches, verbose);

    if (std::filesystem::is_directory(source_path)) {
        yara.addSourceFromDirectory(source_path, false);
    } else {
        yara.addSourceFromFile(source_path);
    }

    yara.initScanner();

    if (std::filesystem::is_directory(target_path)) {
        yara.scanDirectory(target_path, recurse);    
    } else {
        yara.scanFile(target_path);
    }
}



int main(int argc, char *argv[]) {

    CLI::App app{"YaraX scanner"};

    std::string source;
    std::string target;

    bool verbose;
    bool dumpMatches;
    bool recurseDirectories;

    app.add_option("-y, --yara", source, "Path to YaraX rule.")->required();
    app.add_option("-t, --target", target, "Path to the file to scan.")->required();
    
    app.add_flag("-d, --dump", dumpMatches, "Dump each match to the file");
    app.add_flag("-r, --recursive", recurseDirectories, "Scan directories recursively");
    app.add_flag("-v, --verbose", verbose, "Verbose output");

    CLI11_PARSE(app, argc, argv);
    
    start_scanning(source, target, dumpMatches, recurseDirectories, verbose);
}
