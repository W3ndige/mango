#include "Yara.hpp"
#include "yara_x.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>
#include <spdlog/spdlog.h>

Yara::Yara(uint32_t flags) {
    this->dumpMatches = false;

    YRX_RESULT result = yrx_compiler_create(flags, &this->compiler);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to create Yara compiler. Error: {}", yrx_last_error()); 
    }
}


Yara::Yara(uint32_t flags, bool dumpMatches) {
    this->dumpMatches = dumpMatches;

    YRX_RESULT result = yrx_compiler_create(flags, &this->compiler);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to create Yara compiler. Error: {}", yrx_last_error()); 
    }
}


bool Yara::addSource(const char *source) {
    YRX_RESULT result = yrx_compiler_add_source(this->compiler, source);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to add source to compiler. Error: {}", yrx_last_error());
        return false;
    }

    return true;
}

bool Yara::addSourceFromFile(std::filesystem::path path) {
    std::ifstream sourceFile(path, std::ios::in | std::ios::ate);
    if (!sourceFile) {
        spdlog::error("Failed to read source file: {}", path.string());
        return false;
    }

    std::streamsize fileSize = sourceFile.tellg();
    sourceFile.seekg(0, std::ios::beg);

    std::string source(fileSize, '\0');
    sourceFile.read(&source[0], fileSize);

    spdlog::info("Adding {} rule", path.string());

    return addSource(source.c_str());
}

bool Yara::addSourceFromDirectory(std::filesystem::path path, bool recursive) {
    if (!std::filesystem::is_directory(path)) {
        spdlog::error("[{}] is not a directory.", path.string());
        return false;
    }
    
    if (recursive) {
        for (auto &entry : std::filesystem::recursive_directory_iterator(path)) {
            this->addSourceFromFile(entry.path());
        }

    } else {
        for (auto &entry : std::filesystem::directory_iterator(path)) {
            this->addSourceFromFile(entry.path());
        }
    }

    
    return true;
}

bool Yara::initScanner() {
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
    
    result = yrx_scanner_on_matching_rule(scanner, this->onMatchingCb, this);

    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to add on match callback. Error: {}", yrx_last_error());
        return false;
    }
    return true;
}

void Yara::cleanResults() {
    this->results.clear();
}

void Yara::addOnFullMatchCallback(FullMatchCb callback) {
    this->on_full_match_callback = callback;
}


bool Yara::scanFile(std::filesystem::path path) {

    spdlog::info("[{}] Scanning...", path.string());

    std::ifstream scannedFile(path, std::ios::binary | std::ios::ate);
    if (!scannedFile) {
        spdlog::error("Failed to open binary: {}", path.string());
        return false;
    }

    std::streamsize fileSize = scannedFile.tellg();
    scannedFile.seekg(0, std::ios::beg);

    this->current_file_data = std::vector<uint8_t>(fileSize);
    
    if (!scannedFile.read(reinterpret_cast<char *>(current_file_data.data()), fileSize)) {
        spdlog::error("Failed to read binary");
        return false;
    }
    
    this->current_file = path;
    YRX_RESULT result = yrx_scanner_scan(scanner, current_file_data.data(), fileSize);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to scan the binary. Error: {}", yrx_last_error());
        return false;
    }

    while (active_callbacks > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return this->getMatchedIdentifiersForFile(path).size() > 0;
}

bool Yara::scanDirectory(std::filesystem::path path, bool recursive) {
    if (!std::filesystem::is_directory(path)) {
        spdlog::error("[{}] is not a directory.", path.string());
        return false;
    }
    
    if (recursive) {
        for (auto &entry : std::filesystem::recursive_directory_iterator(path)) {
            this->scanFile(entry.path());
        }

    } else {
        for (auto &entry : std::filesystem::directory_iterator(path)) {
            this->scanFile(entry.path());
        }
    }

    
    return true;
}

RuleMap Yara::getMatchedIdentifiersForFile(std::filesystem::path path) {
    if (!this->results.empty()) {
        return this->results[path];
    }

    return RuleMap();
} 

void Yara::onMatchingCb(const struct YRX_RULE *rule, void *data) {
    Yara *yara = static_cast<Yara*>(data);
    
    yara->active_callbacks++;

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
    
    yara->current_rule = identifierString;
    
    result = yrx_rule_iter_patterns(rule, Yara::onPatternCb, data);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to iterate over patterns. Error: {}", yrx_last_error());
        return;
    }

    yara->active_callbacks--;
}


void Yara::onPatternCb(const struct YRX_PATTERN *pattern, void *data) {
    Yara *yara = static_cast<Yara*>(data);
    
    yara->active_callbacks++;

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
    yara->current_pattern = identifierString;

    result = yrx_pattern_iter_matches(pattern, onPatternMatchesCb, data);
    if (result != YRX_RESULT::SUCCESS) {
        spdlog::error("Failed to iterate over pattern matches. Error: {}", yrx_last_error());
        return;
    }

    yara->active_callbacks--;
}


void Yara::onPatternMatchesCb(const struct YRX_MATCH *match, void *data) {
    Yara *yara = static_cast<Yara*>(data);
    
    yara->active_callbacks++;

    yara->results[yara->current_file][yara->current_rule][yara->current_pattern].push_back(std::make_tuple(match->offset, match->length));
    spdlog::info("[{}] Matched {}:{} at {}..{}+{}", yara->current_file.string(), yara->current_rule, yara->current_pattern, match->offset, match->offset, match->length);
    
    if (yara->dumpMatches) {
        bool dumped = yara->dumpMatch(match);
    }

    yara->active_callbacks--;
}


bool Yara::dumpMatch(const struct YRX_MATCH *match) { 

    std::string matchFileName = std::format("{}/{}_{}_{}", "./dumps", this->current_file.filename().string(), this->current_rule, this->current_pattern);

    std::ofstream matchFile(matchFileName, std::ios::binary);

    if (!matchFile) {
        spdlog::error("Failed to open {}", matchFileName);
        return false;

    }

    std::vector<uint8_t> matchBuffer = std::vector<uint8_t>(
            this->current_file_data.begin() + match->offset, 
            this->current_file_data.begin() + match->offset + match->length
    );

    
    spdlog::info("[{}] Dumping match to {}", this->current_file.string(), matchFileName);

    matchFile.write(reinterpret_cast<const char *>(matchBuffer.data()), matchBuffer.size());
    matchFile.close();

    return true;

}

Yara::~Yara() {
    yrx_compiler_destroy(compiler);
}

