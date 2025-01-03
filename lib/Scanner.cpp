#include "Scanner.hpp"
    

Scanner::Scanner() : app("YaraX scanner") {

    bool verbose                = false;
    bool dumpMatches            = false;
    bool recurseDirectories     = false;
    
    app.add_option("-y, --yara", this->sourcePath, "Path to YaraX rule.")->required();
    app.add_option("-t, --target", this->targetPath, "Path to the file to scan.")->required();
    
    app.add_flag("-v, --verbose", this->verbose, "Verbose output");
    app.add_flag("-d, --dump", this->dumpMatches, "Dump each match to the file");
    app.add_flag("-r, --recursive", this->recursiveScan, "Scan directories recursively");

}

int Scanner::parseArguments(int argc, char *argv[]) {
    CLI11_PARSE(app, argc, argv);
    return 0;
}

bool Scanner::scan() {
    std::filesystem::path source_path = this->sourcePath;
    std::filesystem::path target_path = this->targetPath;
        
    Yara yara = Yara(0, this->dumpMatches, this->verbose);

    if (std::filesystem::is_directory(source_path)) {
        yara.addSourceFromDirectory(source_path, false);
    } else {
        yara.addSourceFromFile(source_path);
    }

    yara.initScanner();

    if (std::filesystem::is_directory(target_path)) {
        yara.scanDirectory(target_path, this->recursiveScan);    
    } else {
        yara.scanFile(target_path);
    }

    return true;
} 

Scanner::~Scanner() = default; 
