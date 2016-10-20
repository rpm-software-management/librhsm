cmake_minimum_required (VERSION 2.8.5)
project (librhsm C)

include (GNUInstallDirs)

find_package (PkgConfig REQUIRED)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.44.0)
pkg_check_modules (GOBJECT REQUIRED gobject-2.0>=2.44.0)
pkg_check_modules (GIO REQUIRED gio-2.0>=2.44.0)
pkg_check_modules (JSON_GLIB REQUIRED json-glib-1.0)
pkg_check_modules (OPENSSL REQUIRED openssl)

add_subdirectory (rhsm)
