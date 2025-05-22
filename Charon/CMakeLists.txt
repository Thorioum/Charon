# CMakeList.txt : CMake project for Charon, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (Charon  "include/memory.hpp" "src/memory.cpp" "src/main.cpp" "src/util.cpp" "src/manualmapper.cpp" )

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Charon PROPERTY CXX_STANDARD 20)
endif()

#includes
include(FetchContent)

FetchContent_Declare (
	spdlog 
	URL https://github.com/gabime/spdlog/archive/refs/tags/v1.15.0.zip
	DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable (spdlog)
target_link_libraries(Charon PRIVATE spdlog::spdlog)	
