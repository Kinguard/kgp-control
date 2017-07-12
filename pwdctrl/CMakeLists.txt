


aux_source_directory( . PWD_SRC )

list( APPEND PWD_SRC "${PROJECT_SOURCE_DIR}/PasswordFile.cpp")

add_executable( pwdctrl ${PWD_SRC})

target_link_libraries( pwdctrl
	${LIBOPI_LDFLAGS}
	)

install( TARGETS pwdctrl DESTINATION sbin )

