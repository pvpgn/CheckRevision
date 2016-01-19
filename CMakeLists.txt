cmake_minimum_required (VERSION 3.4)
project (CheckRevision CXX)

include_directories(src)

add_library(CheckRevision SHARED src/modexp.def src/checkrevision.cpp src/checkrevision.h src/dllmain.cpp src/util.cpp src/util.h)

target_link_libraries(CheckRevision version.lib)