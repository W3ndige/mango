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
