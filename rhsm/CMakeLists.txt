set (RHSM_SRCS
     rhsm-entitlement-certificate.c
     rhsm-product-certificate.c
     rhsm-repo.c)
set (RHSM_HDRS
     rhsm-entitlement-certificate.h
     rhsm-product-certificate.h
     rhsm-repo.h
     rhsm.h)

add_library (librhsm SHARED ${RHSM_SRCS})
set_target_properties (librhsm PROPERTIES
                       OUTPUT_NAME rhsm
                       SOVERSION 0)
target_compile_definitions (librhsm
                            PRIVATE -DRHSM_COMPILATION)
target_include_directories (librhsm
                            PRIVATE ${GLIB_INCLUDE_DIRS}
                            PUBLIC ${GOBJECT_INCLUDE_DIRS}
                            PUBLIC ${GIO_INCLUDE_DIRS}
                            PUBLIC ${JSON_GLIB_INCLUDE_DIRS}
                            PRIVATE ${OPENSSL_INCLUDE_DIRS}
                            PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")
target_link_libraries (librhsm
                       ${GLIB_LIBRARIES}
                       ${GOBJECT_LIBRARIES}
                       ${GIO_LIBRARIES}
                       ${JSON_GLIB_LIBRARIES}
                       ${OPENSSL_LIBRARIES})

configure_file (librhsm.pc.in librhsm.pc @ONLY)

install (TARGETS librhsm
         LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install (FILES ${RHSM_HDRS}
         DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/rhsm)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/librhsm.pc
         DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
