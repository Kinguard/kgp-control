project(opi-control)
cmake_minimum_required(VERSION 2.8)

include( FindPkgConfig )
pkg_check_modules ( LIBUTILS REQUIRED libutils>=1.0 )
pkg_check_modules ( LIBJSONCPP REQUIRED libjsoncpp>=1.0 )
pkg_check_modules ( LIBSSL REQUIRED libssl )

set (OPI_CONTROL_VERSION_MAJOR 1)
set (OPI_CONTROL_VERSION_MINOR 0)
set (OPI_CONTROL_APP_NAME "opi-control")

if(CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
	set ( OPI_BUILD_PACKAGE 1 )
else()
	set ( OPI_BUILD_LOCAL 1 )
	#message( ${CMAKE_BUILD_TYPE} )
endif()

configure_file (
	"${PROJECT_SOURCE_DIR}/Config.h.in"
	"${PROJECT_SOURCE_DIR}/Config.h"
)

add_definitions(
		-DNS_ENABLE_SSL
		-DMONGOOSE_NO_CGI
		-DMONGOOSE_NO_DAV
		-DMONGOOSE_NO_AUTH
	 )

aux_source_directory(. SRC_LIST)

include_directories (
		"${LIBJSONCPP_INCLUDE_DIRS}"
	)

add_definitions( -std=c++11 )
add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries( ${PROJECT_NAME} -ljsoncpp ${LIBSSL_LDFLAGS} ${LIBJSONCPP_LDFLAGS} ${LIBUTILS_LDFLAGS} )

install( TARGETS opi-control DESTINATION sbin )
install( DIRECTORY html/ DESTINATION  share/opi-control/web )
