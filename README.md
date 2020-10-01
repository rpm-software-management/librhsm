librhsm
=======

Known limitations:

* Entitlement certificates v1 are not supported
* Multiple products in one product certificate are not supported

Requirements
------------

Following tools and libraries are required to be able to build librhsm library:

* meson (at least 0.37.0)
* ninja
* gcc
* pkg-config
* glib-2.0 (at least 2.44)
* gobject-2.0 (at least 2.44)
* gio-2.0 (at least 2.44)
* json-glib-1.0 (at least 1.2)
* openssl

Installation
------------

When required tools and libraries are installed, then it is possible to build
librhsm using following steps:


```
$ mkdir ../librhsm_build
$ meson ../librhsm_build
$ cd ../librhsm_build
$ ninja-build
```