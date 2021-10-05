cmake_minimum_required(VERSION 3.13)
project(SEALtest VERSION 3.7.1 LANGUAGES CXX)
find_package(SEAL 3.7.1 EXACT REQUIRED)
find_package(OpenMP)
if (OPENMP_FOUND)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

add_executable(mnist_ckks)
target_sources(mnist_ckks
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/mnist_ckks.cpp
)
add_executable(mnist_bfv)
target_sources(mnist_bfv
	PRIVATE
		${CMAKE_CURRENT_LIST_DIR}/mnist_bfv.cpp
)
if(TARGET SEAL::seal)
	target_link_libraries(mnist_ckks PRIVATE SEAL::seal)
	target_link_libraries(mnist_bfv PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
	target_link_libraries(mnist_ckks PRIVATE SEAL::seal_shared)
	target_link_libraries(mnist_bfv PRIVATE SEAL::seal_shared)
endif()
