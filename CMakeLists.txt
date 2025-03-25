add_executable(sandbox2_static_sandbox
  static_sandbox.cc
)
add_executable(sandbox2::static_sandbox ALIAS sandbox2_static_sandbox)
add_dependencies(sandbox2_static_sandbox
  sandbox2::static_bin
)
target_link_libraries(sandbox2_static_sandbox PRIVATE
  absl::check
  absl::flags
  absl::flags_parse
  absl::log
  absl::log_globals
  absl::log_initialize
  absl::log_severity
  absl::time
  sandbox2::bpf_helper
  sapi::runfiles
  sandbox2::sandbox2
  sapi::base
)

# sandboxed_api/sandbox2/examples/static:static_bin
add_executable(sandbox2_static_bin
  static_bin.cc
)
set_target_properties(sandbox2_static_bin PROPERTIES OUTPUT_NAME static_bin)
add_executable(sandbox2::static_bin ALIAS sandbox2_static_bin)
target_link_libraries(sandbox2_static_bin PRIVATE
  sapi::base
  -static-pie  # Fully static link
)
