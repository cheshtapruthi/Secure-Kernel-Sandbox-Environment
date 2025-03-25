#include <fcntl.h>
#include <sys/mman.h>
#include <syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/flags/parse.h"
#include "absl/log/globals.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/base/log_severity.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "sandboxed_api/config.h"
#include "sandboxed_api/sandbox2/executor.h"
#include "sandboxed_api/sandbox2/limits.h"
#include "sandboxed_api/sandbox2/policy.h"
#include "sandboxed_api/sandbox2/policybuilder.h"
#include "sandboxed_api/sandbox2/result.h"
#include "sandboxed_api/sandbox2/sandbox2.h"
#include "sandboxed_api/sandbox2/util/bpf_helper.h"
#include "sandboxed_api/util/runfiles.h"

std::unique_ptr<sandbox2::Policy> GetPolicy() {
  return sandbox2::PolicyBuilder()
      .AllowRead()
      .AllowStaticStartup()
      .AllowSyscall(__NR_getpid)

      .AddPolicyOnSyscall(__NR_write,
                          {
                              ARG_32(0),
                              JEQ32(1, ALLOW),
                              JEQ32(2, ALLOW),
                          })

      .AllowPrctlSetName()

      .AddPolicyOnSyscall(__NR_mprotect,
                          {
                              ARG_32(2),
                              JEQ32(PROT_READ, ALLOW),
                              JEQ32(PROT_NONE, ALLOW),
                              JEQ32(PROT_READ | PROT_WRITE, ALLOW),
                              JEQ32(PROT_READ | PROT_EXEC, ALLOW),
                          })

      .AddPolicyOnSyscall(
          __NR_exit_group,
          {
              ARG_32(0),
              JNE32(0, KILL),
              ALLOW,
          })

      .AllowSyscall(__NR_exit_group)

      .BlockSyscallsWithErrno(
          {
#ifdef __NR_access
              __NR_access,
#endif
              __NR_faccessat,

#ifdef __NR_open
              __NR_open,
#endif
              __NR_openat,
          },
          ENOENT)
      .BuildOrDie();
}

int main(int argc, char* argv[]) {
  if constexpr (sapi::sanitizers::IsAny()) {
    return EXIT_SUCCESS;
  }
  absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();
  const std::string path = sapi::internal::GetSapiDataDependencyFilePath(
      "sandbox2/examples/static/static_bin");
  std::vector<std::string> args = {path};
  auto executor = std::make_unique<sandbox2::Executor>(path, args);

  executor
      ->set_enable_sandbox_before_exec(true)
      .limits()
      ->set_rlimit_fsize(1024 * 1024)
      .set_rlimit_cpu(60)
      .set_walltime_limit(absl::Seconds(30));

  int proc_version_fd = open("/proc/version", O_RDONLY);
  PCHECK(proc_version_fd != -1);

  // Map this fils to sandboxee's stdin.
  executor->ipc()->MapFd(proc_version_fd, STDIN_FILENO);

  auto policy = GetPolicy();
  sandbox2::Sandbox2 s2(std::move(executor), std::move(policy));

  // Let the sandboxee run (synchronously).
  sandbox2::Result result = s2.Run();

  LOG(INFO) << "Final execution status: " << result.ToString();

  return result.final_status() == sandbox2::Result::OK ? EXIT_SUCCESS
                                                       : EXIT_FAILURE;
}
