# Information cmake
cmake_minimum_required(VERSION 3.0.2)

# set variables

# add subdirectory
add_subdirectory( ../libraries/spdlog build/spdlog )
add_subdirectory( ../libraries/args build/args )

# add executable and target libraries
add_executable(exorcise main.cpp)

target_include_directories (exorcise PRIVATE 
		../include/
		../packages/
		../interfaces/
		../libraries/
		../drivers
)

file(GLOB_RECURSE SOURCES
        *.cpp
)

target_sources(exorcise PRIVATE 
		${SOURCES}
)


target_link_libraries(exorcise PRIVATE spdlog::spdlog  -lyara pthread ssl -lz -lmagic -ljansson crypto)
