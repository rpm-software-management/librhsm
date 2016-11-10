project('librhsm', 'c',
        license : 'LGPL-2.1+',
        default_options : [
          'b_asneeded=True',
          'b_lundef=True',
          'c_std=gnu11',
          'warning_level=2',
        ],
        meson_version : '>=0.35.0')

glib = dependency('glib-2.0', version : '>=2.44.0')
gobject = dependency('gobject-2.0', version : '>=2.44.0')
gio = dependency('gio-2.0', version : '>=2.44.0')
json_glib = dependency('json-glib-1.0')
openssl = dependency('openssl')

subdir('rhsm')
