
add_library(bandersnatch_vrfs-cpp
    ./bandersnatch_vrfs.cpp
)
add_dependencies(bandersnatch_vrfs-cpp
    cargo_build
)

target_include_directories(bandersnatch_vrfs-cpp PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

install(
    TARGETS bandersnatch_vrfs-cpp EXPORT bandersnatch_vrfs_crust_targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bandersnatch_vrfs-cpp
)
