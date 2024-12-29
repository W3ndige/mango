#define CATCH_CONFIG_MAIN

#include <catch2/catch_test_macros.hpp>

#include "Yara.hpp"

TEST_CASE("Test basic Yara scan", "[Yara]") {
    Yara yara(0);

    REQUIRE_NOTHROW(yara.addSourceFromFile("../tests/files/test.yara"));

    REQUIRE_NOTHROW(yara.initScanner());

    SECTION("File contains a match") {
        // Test a file expected to return true
        bool result = yara.scanFile("../tests/files/match_foo_test.txt");
        REQUIRE(result == true);
    }
    
    /*
    SECTION("File does not contain a match") {
        // Test a file expected to return false
        bool result = yara.scanFile("../tests/files/no_match_foo_test.txt");
        REQUIRE(result == false);
    }
    */ 
}

TEST_CASE("Tests if there are any identifiers saved from the match.", "[Yara Matched Identifiers]") {
    Yara yara(0);

    REQUIRE_NOTHROW(yara.addSourceFromFile("../tests/files/test.yara"));

    REQUIRE_NOTHROW(yara.initScanner());

    bool result = yara.scanFile("../tests/files/match_foo_test.txt");
    REQUIRE(result == true);
    REQUIRE(yara.getMatchedIdentifiersForFile("../tests/files/match_foo_test.txt").size() > 0);
}

TEST_CASE("Tests if there are none identifiers with invalid path that was never scanned..", "[Yara Matched Identifiers for Invalid Path]") {
    Yara yara(0);

    REQUIRE_NOTHROW(yara.addSourceFromFile("../tests/files/test.yara"));

    REQUIRE_NOTHROW(yara.initScanner());

    bool result = yara.scanFile("../tests/files/match_foo_test.txt");
    REQUIRE(result == true);
    REQUIRE(yara.getMatchedIdentifiersForFile("../tests/files/match_foo.txt").size() == 0);
}

TEST_CASE("Test adding invalid rule", "[Yara Invalid Rule]") {
    Yara yara(0);

    REQUIRE(yara.addSourceFromFile("../tests/files/test_invalid_rule.yara") == false);
}

