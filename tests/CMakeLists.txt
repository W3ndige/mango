find_package(Catch2 3 REQUIRED)

# Add test executable
add_executable(test_yara test_yara.cpp)

set_target_properties(test_yara PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests
)

# Link test executable with Yara and Catch2
target_link_libraries(test_yara PRIVATE Yara Catch2::Catch2WithMain)

# Register the tests
include(Catch)
catch_discover_tests(test_yara)
