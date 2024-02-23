cmake_minimum_required(VERSION 3.0.2)

include(GoogleTest)

file(COPY rules DESTINATION .)

# add subdirectory
add_subdirectory( ../../libraries/googletest build/googletest)

add_definitions(-DUNIT_TESTS)
set(PROJECT_SOURCES
	../../sources/yara/yara.cpp
	yara_tests.cpp
)

add_executable(engine_test_yara ${PROJECT_SOURCES})

target_include_directories (engine_test_yara  PRIVATE 
		../../include/
		../../interfaces/
		../../../packages/
)


target_link_libraries(engine_test_yara  gtest gtest_main  spdlog::spdlog -lyara pthread ssl -lz -lmagic -ljansson crypto)