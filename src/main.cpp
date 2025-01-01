#include "Yara.hpp"

#include <filesystem>
#include <CLI/CLI.hpp>


void start_scanning(std::string source, std::string target, bool dumpMatches, bool recurse) {
    std::filesystem::path source_path = source;
    std::filesystem::path target_path = target;
    
    Yara yara = Yara(0, dumpMatches);

    if (std::filesystem::is_directory(source_path)) {
        for (auto &entry : std::filesystem::directory_iterator(source_path)) {
            if (entry.is_regular_file() && (entry.path().extension().string() == ".yara" || entry.path().extension().string() == ".yar")) {
                yara.addSourceFromFile(entry);
            }
        }
    } else {
        yara.addSourceFromFile(source.c_str());
    }

    yara.initScanner();



    if (std::filesystem::is_directory(target_path)) {
        if (recurse) {
            for (auto &entry : std::filesystem::recursive_directory_iterator(target_path)) {
                if (entry.is_regular_file()) {
                    yara.scanFile(entry.path().c_str());
                }
            }
        } else {
            for (auto &entry : std::filesystem::directory_iterator(target_path)) {
                if (entry.is_regular_file()) {
                    yara.scanFile(entry.path().c_str());
                }
            }
        }

   } else {
        yara.scanFile(target.c_str());
    }
}



int main(int argc, char *argv[]) {

    CLI::App app{"YaraX scanner"};

    std::string source;
    std::string target;

    bool dumpMatches;
    bool recurseDirectories;

    app.add_option("-y, --yara", source, "Path to YaraX rule.")->required();
    app.add_option("-t, --target", target, "Path to the file to scan.")->required();
    
    app.add_flag("-d, --dump", dumpMatches, "Dump each match to the file");
    app.add_flag("-r, --recursive", recurseDirectories, "Scan directories recursively");

    CLI11_PARSE(app, argc, argv);
    
    start_scanning(source, target, dumpMatches, recurseDirectories);
}
