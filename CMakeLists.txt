cmake_minimum_required(VERSION 3.12)

find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
  set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif (CCACHE_FOUND)

option(TESTING "Enable tests" OFF)
option(BENCHMARK "Enable benchmark" OFF)

if (TESTING OR BENCHMARK)
  include("cmake/3rdparty/Hunter/init.cmake")
  HunterGate(
      URL  https://github.com/qdrvm/hunter/archive/refs/tags/v0.23.257-qdrvm11.tar.gz
      SHA1 b2a69ae501bdc99006fb86e55930640004468556
  )
endif ()

project(bandersnatch_vrfs-crust C CXX)

include(FindPackageHandleStandardArgs)
include(cmake/functions.cmake)

include(cmake/rust.cmake)

if (NOT EXISTS "${CMAKE_TOOLCHAIN_FILE}")
  # https://cgold.readthedocs.io/en/latest/tutorials/toolchain/globals/cxx-standard.html#summary
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif ()

if (TESTING)
  enable_testing()
  add_subdirectory(test)
endif ()

if (BENCHMARK)
  add_subdirectory(benchmark)
endif ()

# TODO: Consider changing to CMake 3.23 FILE_SETs
install(
    DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

#export(EXPORT bandersnatch_vrfs_crust_targets
#  FILE "${CMAKE_CURRENT_BINARY_DIR}/bandersnatch_vrfs_crust/bandersnatch_vrfs_crustTargets.cmake"
#  NAMESPACE bandersnatch_vrfs_crust::
#)
configure_file(cmake/bandersnatch_vrfs_crustConfig.cmake
  "${CMAKE_CURRENT_BINARY_DIR}/bandersnatch_vrfs_crust/bandersnatch_vrfs_crustConfig.cmake"
  COPYONLY
)

set(ConfigPackageLocation lib/cmake/bandersnatch_vrfs_crust)
#install(EXPORT bandersnatch_vrfs_crust_targets
#  FILE
#    bandersnatch_vrfs_crustTargets.cmake
#  NAMESPACE
#    bandersnatch_vrfs_crust::
#  DESTINATION
#    ${ConfigPackageLocation}
#)
install(
  FILES
    cmake/bandersnatch_vrfs_crustConfig.cmake
  DESTINATION
    ${ConfigPackageLocation}
)
