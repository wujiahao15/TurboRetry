project('dpdk_qia', 'c')
 
dpdk = dependency('libdpdk')
allow_experimental_apis = true
sources = files(
    'quic_initial_attack.c'
)

enable_profile = get_option('PROFILE')
if enable_profile
  add_project_arguments('-DPROFILE', language: ['c', 'cpp'])
endif

enable_short = get_option('SHORT')
if enable_short
  add_project_arguments('-DSHORT', language: ['c', 'cpp'])
endif

executable('dpdk_qia', sources, dependencies: dpdk, install: false)