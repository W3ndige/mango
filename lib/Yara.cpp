#include "Yara.hpp"
#include "yara_x.h"

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

void Yara::iterate_matches(const struct YRX_RULE *rule, ScanResult *scan_result) {
    YRX_RESULT result = yrx_rule_iter_patterns(rule, Yara::on_pattern_cb, scan_result);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to iterate over patterns. Error: {}", yrx_last_error());
        return;
    }
    
    return;
}

void Yara::on_matching_cb(const struct YRX_RULE *rule, void *data) {
    Yara *yara = static_cast<Yara*>(data);

    ScanResult scan_result = ScanResult {}; 
    scan_result.initialized = false;
    scan_result.exception = false;

    scan_result.file = yara->current_file;
    
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

    scan_result.ruleName = identifierString;
    
    iterate_matches(rule, &scan_result);
    
}


void Yara::on_pattern_cb(const struct YRX_PATTERN *pattern, void *data) {
    ScanResult *scan_result = static_cast<ScanResult*>(data);
    
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
    
    scan_result->pattern = identifierString;
    

    result = yrx_pattern_iter_matches(pattern, on_pattern_iter_matches, &data);

    spdlog::info("[{}] Matched {}:{}", scan_result->file, scan_result->ruleName, scan_result->pattern);
}



void Yara::on_pattern_iter_matches(const struct YRX_MATCH *match, void *data) {
    ScanResult *scan_result = static_cast<ScanResult*>(data);
    
    



}


Yara::~Yara() {
    yrx_compiler_destroy(compiler);
}

