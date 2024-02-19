project(
  'cm4all-image-cloak',
  'c',
  version: '0.1',
  meson_version: '>= 0.56',
  default_options: [
    'c_std=c17',
    'warning_level=3',
  ],
)

compiler = meson.get_compiler('c')

common_cppflags = [
  '-D_GNU_SOURCE',
]

test_global_common_flags = [
  '-fvisibility=hidden',
]

test_common_flags = [
  '-Wcast-qual',
  '-Wcast-align',
  '-Wdouble-promotion',
  '-Wmissing-declarations',
  '-Wmissing-format-attribute',
  '-Wmissing-noreturn',
  '-Wredundant-decls',
  '-Wshadow',
  '-Wundef',
  '-Wvla',
  '-Wwrite-strings',

  # clang specific warning options:
  '-Wunreachable-code-aggressive',
  '-Wused-but-marked-unused',
]

test_global_cflags = test_global_common_flags + [
]

test_cflags = test_common_flags + [
]

test_ldflags = [
]

if get_option('buildtype') != 'debug'
  test_global_cflags += [
    '-ffunction-sections',
    '-fdata-sections',
  ]
  test_ldflags += [
    '-Wl,--gc-sections',
    '-Wl,--icf=all',
  ]
endif

add_global_arguments(common_cppflags, language: 'c')
add_global_arguments(compiler.get_supported_arguments(test_global_cflags), language: 'c')
add_project_arguments(compiler.get_supported_arguments(test_cflags), language: 'c')
add_project_link_arguments(compiler.get_supported_link_arguments(test_ldflags), language: 'c')

executable(
  'cm4all-image-cloak',
  'src/main.c',
  'src/efi.c',
  'src/hex.c',
  'src/io.c',
  dependencies: [
    dependency('libsodium'),
  ],
  install: true
)
