#include "Yara.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <vector>
#include <spdlog/spdlog.h>


Yara::Yara(uint32_t flags) {
    YRX_RESULT result = yrx_compiler_create(flags, &this->compiler);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to create Yara compiler. Error: {}", yrx_last_error()); 
    }
}


bool Yara::add_source(const char *source) {
    YRX_RESULT result = yrx_compiler_add_source(this->compiler, source);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to add source to compiler. Error: {}", yrx_last_error());
        return false;
    }

    return true;
}

bool Yara::add_source_from_file(const char *path) {
    std::ifstream sourceFile(path, std::ios::in | std::ios::ate);
    if (!sourceFile) {
        spdlog::error("Failed to read source file: {}", path);
        return false;
    }

    std::streamsize fileSize = sourceFile.tellg();
    sourceFile.seekg(0, std::ios::beg);

    std::string source(fileSize, '\0');
    sourceFile.read(&source[0], fileSize);

    return add_source(source.c_str());
}


bool Yara::init_scanner() {
    this->rules = yrx_compiler_build(this->compiler);

    if (this->rules == nullptr) {
        spdlog::error("Can't create a scanner. Rules have not been initialized");
        return false;
    }
    
    YRX_RESULT result = yrx_scanner_create(rules, &this->scanner);

    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to initialize scanner. Error: {}", yrx_last_error());
        return false;
    }
    
    result = yrx_scanner_on_matching_rule(scanner, this->on_matching_cb, this);

    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to add on match callback. Error: {}", yrx_last_error());
        return false;
    }

    return true;
}

void Yara::clean_results() {
    this->results.clear();
}


bool Yara::scan_file(const char *path) {
    std::ifstream scannedFile(path, std::ios::binary | std::ios::ate);
    if (!scannedFile) {
        spdlog::error("Failed to open binary: {}", path);
        return false;
    }

    std::streamsize fileSize = scannedFile.tellg();
    scannedFile.seekg(0, std::ios::beg);

    std::vector<uint8_t> fileData(fileSize);

    if (!scannedFile.read(reinterpret_cast<char *>(fileData.data()), fileSize)) {
        spdlog::error("Failed to read binary");
        return false;
    }
    
    this->current_file = path;
    YRX_RESULT result = yrx_scanner_scan(scanner, fileData.data(), fileSize);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to scan the binary. Error: {}", yrx_last_error());
        return false;
    }

    return true;
}

std::vector<const char *> Yara::getMatchedIdentifiersForFile(const char *path) {
    if (this->results.count(path) > 0) {
        return this->results[path];
    } 

    return std::vector<const char *>();

} 

void Yara::on_matching_cb(const struct YRX_RULE *rule, void *data) {
    Yara *yara = static_cast<Yara*>(data);

    const uint8_t *identifier = nullptr;
    size_t identifierLength = 0;

    YRX_RESULT result = yrx_rule_identifier(rule, &identifier, &identifierLength);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to recover the identifier of a rule. Error: {}", yrx_last_error());
        return;
    }

    char *identifierString = new char[identifierLength + 1];
    std::memcpy(identifierString, identifier, identifierLength);
    identifierString[identifierLength] = '\0';
    
    yara->results[yara->current_file].push_back(identifierString);

    result = yrx_rule_iter_patterns(rule, Yara::on_pattern_cb, data);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to iterate over patterns. Error: {}", yrx_last_error());
        return;
    }
    
}


void Yara::on_pattern_cb(const struct YRX_PATTERN *pattern, void *data) {
    Yara *yara = static_cast<Yara*>(data);
   
    const uint8_t *identifier = nullptr;
    size_t identifierLength = 0;

    YRX_RESULT result = yrx_pattern_identifier(pattern, &identifier, &identifierLength);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to recover the identifier of a pattern. Error: {}", yrx_last_error());
        return;
    }

    char *identifierString = new char[identifierLength + 1];
    std::memcpy(identifierString, identifier, identifierLength);
    identifierString[identifierLength] = '\0';
    

    result = yrx_pattern_iter_matches(pattern, on_pattern_matches_cb, &data);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to iterate over pattern matches. Error: {}", yrx_last_error());
        return;
    }
 
}


void Yara::on_pattern_matches_cb(const struct YRX_MATCH *match, void *data) {
     Yara *yara = static_cast<Yara*>(data);
   
}


Yara::~Yara() {
    yrx_compiler_destroy(compiler);
}

