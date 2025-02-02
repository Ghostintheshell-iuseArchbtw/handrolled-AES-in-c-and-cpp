cmake_minimum_required(VERSION 3.10)
project(aes_implementation C)

# Windows-specific settings first
if(WIN32)
    # Force Visual Studio to use console subsystem
    add_definitions(-D_CONSOLE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")
    
    # Disable CRT secure warnings
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Add library
add_library(aes STATIC
    build/aes1.c
)

# Set include directories
target_include_directories(aes 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/build
)

# Add test executable
add_executable(aes_test
    test/main.c
)

# Link library statically
target_link_libraries(aes_test PRIVATE aes)

# Compiler flags
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # GCC/Clang flags
    add_compile_options(-Wall -Wextra -O2)
    set_target_properties(aes PROPERTIES POSITION_INDEPENDENT_CODE ON)
elseif(MSVC)
    # MSVC flags
    add_compile_options(/W4 /O2)
endif()

# Install rules (optional)
install(TARGETS aes
    RUNTIME DESTINATION bin
) 