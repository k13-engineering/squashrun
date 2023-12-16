project('universe', 'c', default_options: [
  'debug=true',
  'optimization=0',
  'werror=true'
])

add_project_arguments(
'-Wno-error=unused-function',
'-Wno-error=unused-variable',
'-finstrument-functions',
'-fstack-protector-all',
language: 'c'
)

init = executable('squashrun', 'src/main.c', link_args: ['-static'])
