
add_library(bandersnatch_vrfs_cpp
    ./bandersnatch_vrfs.cpp
)

#add_dependencies(bandersnatch_vrfs_cpp
#    cargo_build
#)

target_link_libraries(bandersnatch_vrfs_cpp
  bandersnatch_vrfs_crust
)

target_include_directories(bandersnatch_vrfs_cpp PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)

install(
    TARGETS bandersnatch_vrfs_cpp
    EXPORT bandersnatch_vrfs_crust_targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bandersnatch_vrfs-cpp
)
