cmake_minimum_required(VERSION 3.16)
project(mango LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define project directories
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(EXTERNAL_DIR ${CMAKE_SOURCE_DIR}/external)
set(BUILD_DIR ${CMAKE_BINARY_DIR})  # Use binary dir for output

# Specify the build output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})

# Enable verbose compilation for Neovim integration
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find pkg-config and ensure it is available
find_package(PkgConfig REQUIRED)

# Locate yara_x_capi using pkg-config
pkg_check_modules(YARA_X_CAPI REQUIRED yara_x_capi)

# Include the external and library directories
include_directories(${EXTERNAL_DIR} ${LIB_DIR} ${YARA_X_CAPI_INCLUDE_DIRS})

# Link directories from pkg-config
link_directories(${YARA_X_CAPI_LIBRARY_DIRS})

# Add source files for the main executable
file(GLOB_RECURSE SRC_FILES ${SRC_DIR}/*.cpp)

# Add Yara library (lib/Yara.cpp)
add_library(Yara STATIC lib/Yara.cpp)
target_include_directories(Yara PUBLIC ${LIB_DIR})
target_link_libraries(Yara PRIVATE ${YARA_X_CAPI_LIBRARIES})
target_compile_definitions(Yara PRIVATE ${YARA_X_CAPI_CFLAGS_OTHER})
target_compile_options(Yara PRIVATE ${YARA_X_CAPI_CFLAGS})

add_subdirectory(external/spdlog)
target_link_libraries(Yara PRIVATE spdlog::spdlog)

option(ENABLE_ASAN "Enable AddressSanitizer" OFF)

if (ENABLE_ASAN)
    add_compile_options(-fsanitize=address -g)
    add_link_options(-fsanitize=address)
endif()

# Add the main executable target
add_executable(mango ${SRC_FILES})

# Link the main executable with the Yara library and YARA_X_CAPI
target_link_libraries(mango PRIVATE Yara ${YARA_X_CAPI_LIBRARIES})

# Enable testing
enable_testing()

# Add tests subdirectory
add_subdirectory(tests)
