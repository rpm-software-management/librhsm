cmake_minimum_required (VERSION 2.8.5)
project (librhsm C)

set (RHSM_VERSION 0)

include (GNUInstallDirs)

macro(use_c11)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_C_FLAGS "--std=gnu11 ${CMAKE_C_FLAGS}")
    endif ()
  else ()
    set (CMAKE_C_STANDARD 11)
  endif ()
endmacro(use_c11)
use_c11 ()

find_package (PkgConfig REQUIRED)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.44.0)
pkg_check_modules (GOBJECT REQUIRED gobject-2.0>=2.44.0)
pkg_check_modules (GIO REQUIRED gio-2.0>=2.44.0)
pkg_check_modules (JSON_GLIB REQUIRED json-glib-1.0)
pkg_check_modules (OPENSSL REQUIRED openssl)

add_subdirectory (rhsm)
