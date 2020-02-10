add_executable(rbd-fuse
  rbd-fuse.cc)
target_link_libraries(rbd-fuse
  ceph-common librbd librados global ${FUSE_LIBRARIES})
set_target_properties(rbd-fuse PROPERTIES
    COMPILE_FLAGS "-I${FUSE_INCLUDE_DIRS}"
    POSITION_INDEPENDENT_CODE ${EXE_LINKER_USE_PIE})
install(TARGETS rbd-fuse DESTINATION bin)
