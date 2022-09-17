SET(CPACK_GENERATOR "DEB")

set(CPACK_PACKAGE_NAME ${PROJECT_NAME}/${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    CACHE STRING "The resulting package name")
message("CPACK_PACKAGE_NAME = ${CPACK_PACKAGE_NAME}")


# which is useful in case of packing only selected components instead of the whole thing
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Simple C tcp_sniffer application"
    CACHE STRING "Package description for the package metadata")
# set(CPACK_PACKAGE_VENDOR "Some Company" CACHE STRING)

set(CPACK_VERBATIM_VARIABLES YES)

set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})
SET(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_SOURCE_DIR}/_packages")

# https://unix.stackexchange.com/a/11552/254512
set(CPACK_PACKAGING_INSTALL_PREFIX "/")

set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})

set(CPACK_PACKAGE_CONTACT "mikemike111997@gmail.com")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Mykhailo Lohvynenko")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# package name for deb. If set, then instead of some-application-0.9.2-Linux.deb
# you'll get some-application_0.9.2_amd64.deb (note the underscores too)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

# that is if you want every group to have its own package,
# although the same will happen if this is not set (so it defaults to ONE_PER_GROUP)
# and CPACK_DEB_COMPONENT_INSTALL is set to YES
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)#ONE_PER_GROUP)

# without this you won't be able to pack only specified component
set(CPACK_DEB_COMPONENT_INSTALL YES)

set(CPACK_DEBIAN_PACKAGE_DEPENDS "libpcap-dev(>=1.9.1)")

include(CPack)