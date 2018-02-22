srcs = files('rhsm-context.c',
             'rhsm-entitlement-certificate.c',
             'rhsm-product-certificate.c',
             'rhsm-utils.c')
hdrs = files('rhsm-context.h',
             'rhsm-entitlement-certificate.h',
             'rhsm-product-certificate.h',
             'rhsm-utils.h',
             'rhsm.h')
hdrs_private = files('rhsm-utils-private.h')
public_deps = [glib, gobject, gio, json_glib]
private_deps = [openssl]
_librhsm = library(
  'rhsm',
  sources : srcs,
  dependencies : public_deps + private_deps,
  soversion : '0',
  c_args : ['-DRHSM_COMPILATION', '-DG_LOG_DOMAIN="librhsm"'],
  install : true,
)
librhsm = declare_dependency(
  include_directories : include_directories('.'),
  link_with : _librhsm,
  dependencies : public_deps,
)

pkg.generate(
  description : 'Red Hat Subscription Manager library',
  name : meson.project_name(),
  libraries : _librhsm,
  requires : ['glib-2.0 >= 1.2', 'gobject-2.0 >= 2.44', 'gio-2.0 >= 2.44', 'json-glib-1.0 >= 1.2'],
  requires_private : ['openssl'],
  version : meson.project_version(),
)

install_headers(hdrs, subdir : 'rhsm')
