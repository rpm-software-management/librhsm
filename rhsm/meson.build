srcs = files('rhsm-context.c',
             'rhsm-entitlement-certificate.c',
             'rhsm-product-certificate.c',
             'rhsm-utils.c')
hdrs = ['rhsm-context.h',
             'rhsm-entitlement-certificate.h',
             'rhsm-product-certificate.h',
             'rhsm-utils.h',
             'rhsm.h']
hdrs_private = files('rhsm-utils-private.h')
public_deps = [glib, gobject, gio, json_glib]
private_deps = [openssl]
_librhsm = shared_library('rhsm', srcs,
                          dependencies : public_deps + private_deps,
                          soversion : '0',
                          c_args : ['-DRHSM_COMPILATION', '-DG_LOG_DOMAIN="librhsm"'],
                          install : true)
librhsm = declare_dependency (include_directories : include_directories('.'),
                              link_with : _librhsm,
                              dependencies : public_deps)

install_headers(hdrs, subdir : 'rhsm')
