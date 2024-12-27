cmake_minimum_required(VERSION 3.16)
project(mango LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define project directories
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)
set(EXTERNAL_DIR ${CMAKE_SOURCE_DIR}/external)
set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)

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

# Add source files
file(GLOB_RECURSE SRC_FILES ${SRC_DIR}/*.cpp)

# Add the executable target
add_executable(mango ${SRC_FILES})
target_sources(mango PRIVATE lib/Yara.cpp)

# Link the YARA library
target_link_libraries(mango ${YARA_X_CAPI_LIBRARIES})

# Add definitions from pkg-config (if any)
target_compile_definitions(mango PRIVATE ${YARA_X_CAPI_CFLAGS_OTHER})
target_compile_options(mango PRIVATE ${YARA_X_CAPI_CFLAGS})
