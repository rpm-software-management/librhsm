project('librhsm', 'c',
        version : '0.0.4',
        license : 'LGPL-2.1+',
        default_options : [
          'b_asneeded=True',
          'b_lundef=True',
          'c_std=gnu11',
          'warning_level=2',
        ],
        meson_version : '>=0.37.0')

glib = dependency('glib-2.0', version : '>=2.44')
gobject = dependency('gobject-2.0', version : '>=2.44')
gio = dependency('gio-2.0', version : '>=2.44')
json_glib = dependency('json-glib-1.0', version : '>=1.2')
openssl = dependency('openssl')

pkg = import('pkgconfig')

subdir('rhsm')
