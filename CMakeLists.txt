project(opi-control)
cmake_minimum_required(VERSION 2.8)

include( FindPkgConfig )
pkg_check_modules ( LIBOPI REQUIRED libopi>=1.6.42 )
pkg_check_modules ( LIBKGP REQUIRED libkinguard>=1.0.9 )
pkg_check_modules ( LIBSSL REQUIRED openssl )

set (OPI_CONTROL_VERSION_MAJOR 1)
set (OPI_CONTROL_VERSION_MINOR 0)
set (OPI_CONTROL_APP_NAME "opi-control")

configure_file (
	"${PROJECT_SOURCE_DIR}/Config.h.in"
	"${PROJECT_SOURCE_DIR}/Config.h"
)

add_definitions(
		-DMG_ENABLE_SSL
#		-DMG_ENABLE_HTTP_CGI=0
	 )

aux_source_directory(. SRC_LIST)

include_directories (
		"${PROJECT_SOURCE_DIR}"
		"${LIBOPI_INCLUDE_DIRS}"
		"${LIBKGP_INCLUDE_DIRS}"
	)

add_definitions( -std=c++11 -Wall )
add_executable(${PROJECT_NAME} ${SRC_LIST})

add_subdirectory( pwdctrl )

target_link_libraries( ${PROJECT_NAME}
	${LIBOPI_LDFLAGS}
	${LIBKGP_LDFLAGS}
	${LIBSSL_LDFLAGS}
	)

install( TARGETS opi-control DESTINATION sbin )
install( DIRECTORY html/ DESTINATION  share/opi-control/web )
