project(opi-control)
cmake_minimum_required(VERSION 2.8)

include( FindPkgConfig )
pkg_check_modules ( LIBUTILS REQUIRED libutils>=1.0 )
pkg_check_modules ( LIBJSONCPP REQUIRED libjsoncpp>=1.0 )
pkg_check_modules ( LIBSSL REQUIRED libssl )


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
