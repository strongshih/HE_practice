cmake_minimum_required(VERSION 3.13)
project(SEALtest VERSION 3.7.1 LANGUAGES CXX)
find_package(SEAL 3.7.1 EXACT REQUIRED)
add_executable(main)
target_sources(main
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/main.cpp
)
if(TARGET SEAL::seal)
	target_link_libraries(main PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
	target_link_libraries(main PRIVATE SEAL::seal_shared)
endif()
