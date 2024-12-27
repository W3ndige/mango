#define CATCH_CONFIG_MAIN

#include <catch2/catch_test_macros.hpp>

#include "Yara.hpp"

TEST_CASE("Test basic Yara scan", "[Yara]") {
    Yara yara(0);

    REQUIRE_NOTHROW(yara.add_source_from_file("../tests/files/test.yara"));

    // Initialize the scanner
    REQUIRE_NOTHROW(yara.init_scanner());

    SECTION("File contains a match") {
        // Test a file expected to return true
        bool result = yara.scan_file("../tests/files/match_foo_test.txt");
        REQUIRE(result == true);
    }
    
    /*
    SECTION("File does not contain a match") {
        // Test a file expected to return false
        bool result = yara.scan_file("../tests/files/no_match_foo_test.txt");
        REQUIRE(result == false);
    }
    */ 
}

TEST_CASE("Tests if there are any identifiers saved from the match.", "[Yara Matched Identifiers]") {
    Yara yara(0);

    REQUIRE_NOTHROW(yara.add_source_from_file("../tests/files/test.yara"));

    // Initialize the scanner
    REQUIRE_NOTHROW(yara.init_scanner());

    bool result = yara.scan_file("../tests/files/match_foo_test.txt");
    REQUIRE(result == true);
    REQUIRE(yara.getMatchedIdentifiersForFile("../tests/files/match_foo_test.txt").size() > 0);
}


TEST_CASE("Test adding invalid rule", "[Yara Invalid Rule]") {
    Yara yara(0);

    REQUIRE(yara.add_source_from_file("../tests/files/test_invalid_rule.yara") == false);
}

