/**
 * @file        core/seh_posix.cpp
 * @brief       POSIX platform SEH implementations
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 * @license     BSD 3-Clause License
 */

#include <rex/platform.h>
#include <rex/platform/seh.h>

static_assert(REX_PLATFORM_LINUX || REX_PLATFORM_MAC, "This file is POSIX-only");

#include <signal.h>
#include <cstdint>
#include <cstdlib>  // std::abort()
#include <cstdio>
#include <ucontext.h>

#include <rex/logging.h>
#include <rex/platform/exceptions.h>

#if defined(__APPLE__)
#include <dlfcn.h>
#endif

namespace rex::platform {

static thread_local SehThreadState tls_seh_state;
static thread_local bool tls_seh_active = false;

// The handlers installed before ours, captured at install time: faults that
// happen outside SEH-protected code belong to them (the MMIO handler and the
// guest exception machinery chained behind it, then any crash reporter).
// Overwriting the disposition with SIG_DFL here used to kill the process on
// the re-raised signal before any of them — or any logging — ever ran.
static struct sigaction previous_actions[4];  // SIGSEGV, SIGBUS, SIGFPE, SIGILL

static int action_slot(int sig) {
  switch (sig) {
    case SIGSEGV:
      return 0;
    case SIGBUS:
      return 1;
    case SIGFPE:
      return 2;
    case SIGILL:
      return 3;
    default:
      return 0;
  }
}

// Where the faulting (or re-raising) instruction lives, for the last-resort
// log: module path plus offset, like the crash backtraces print.
static uintptr_t fault_pc(void* ucontext) {
  if (!ucontext) {
    return 0;
  }
  auto* uc = reinterpret_cast<ucontext_t*>(ucontext);
#if defined(__aarch64__)
#if defined(__APPLE__)
  return reinterpret_cast<uintptr_t>(uc->uc_mcontext->__ss.__pc);
#else
  return static_cast<uintptr_t>(uc->uc_mcontext.pc);
#endif
#elif defined(__x86_64__) || defined(__i386__)
  return static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RIP]);
#else
  return 0;
#endif
}

static void describe_pc(uintptr_t pc, char* out, size_t out_size) {
  std::snprintf(out, out_size, "0x%llX", static_cast<unsigned long long>(pc));
}

SehThreadState& seh_thread_state() {
  return tls_seh_state;
}

int seh_filter(uint32_t /*code*/, void* /*ep*/) {
  // Not used on POSIX - signal handlers throw directly
  return 0;
}

/// Signal handler for SIGSEGV/SIGBUS/SIGFPE/SIGILL
static void signal_handler(int sig, siginfo_t* info, void* ucontext) {
  // Only handle if we're in SEH-protected code
  if (!tls_seh_active) {
    // Not in SEH-protected code: hand the fault to whatever was installed
    // before this handler (MMIO handling, guest exception dispatch, crash
    // reporters). If none of them handles it, the last one in the chain
    // degrades to the default action; when that is us, log the fault first —
    // silently dying here used to hide every crash outside a guest __try.
    const struct sigaction& previous = previous_actions[action_slot(sig)];
    if ((previous.sa_flags & SA_SIGINFO) && previous.sa_sigaction) {
      previous.sa_sigaction(sig, info, ucontext);
      return;
    }
    if (!(previous.sa_flags & SA_SIGINFO) && previous.sa_handler != SIG_DFL &&
        previous.sa_handler != SIG_IGN && previous.sa_handler) {
      previous.sa_handler(sig);
      return;
    }
    // Nothing below us will report it: log the fault address and PC, then
    // let the default action end the process on the re-raised signal.
    char where[160];
    describe_pc(fault_pc(ucontext), where, sizeof(where));
    REXLOG_ERROR(
        "SEH: unhandled signal {} outside SEH-protected code (fault address "
        "0x{:X}, PC {})",
        sig, info ? reinterpret_cast<uintptr_t>(info->si_addr) : 0,
        where);
    signal(sig, SIG_DFL);
    raise(sig);
    return;
  }

  // Determine exception code based on signal
  SehException::Code code;
  switch (sig) {
    case SIGSEGV:
      code = SehException::ACCESS_VIOLATION;
      break;
    case SIGBUS:
      code = SehException::IN_PAGE_ERROR;
      break;
    case SIGFPE:
      code = SehException::FLOAT_DIVIDE_BY_ZERO;
      break;
    case SIGILL:
      code = SehException::ILLEGAL_INSTRUCTION;
      break;
    default:
      code = SehException::UNKNOWN;
      break;
  }

  // Get fault address
  uintptr_t address = info ? reinterpret_cast<uintptr_t>(info->si_addr) : 0;

  // Store in thread state for potential rethrow
  tls_seh_state.code = static_cast<uint32_t>(code);
  tls_seh_state.info[0] = 0;
  tls_seh_state.info[1] = address;

  // Use libunwind to throw from signal context
  // This works because libunwind can unwind through signal frames
  throw SehException(code, address);
}

[[noreturn]] void seh_rethrow() {
  // Map stored code back to signal and re-raise
  uint32_t code = tls_seh_state.code;
  int sig;
  switch (code) {
    case SehException::ACCESS_VIOLATION:
      sig = SIGSEGV;
      break;
    case SehException::IN_PAGE_ERROR:
      sig = SIGBUS;
      break;
    case SehException::FLOAT_DIVIDE_BY_ZERO:
    case SehException::INTEGER_DIVIDE_BY_ZERO:
      sig = SIGFPE;
      break;
    case SehException::ILLEGAL_INSTRUCTION:
      sig = SIGILL;
      break;
    default:
      abort();
  }
  // Restore default handler and re-raise
  signal(sig, SIG_DFL);
  raise(sig);
  abort();  // Should not reach here
}

void seh_initialize() {
  if (g_seh_initialized.exchange(true)) {
    return;  // Already initialized
  }

  struct sigaction sa;
  sa.sa_sigaction = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;  // SA_NODEFER allows re-entry for nested exceptions

  struct sigaction* previous = nullptr;
  previous = &previous_actions[action_slot(SIGSEGV)];
  sigaction(SIGSEGV, &sa, previous);
  previous = &previous_actions[action_slot(SIGBUS)];
  sigaction(SIGBUS, &sa, previous);
  previous = &previous_actions[action_slot(SIGFPE)];
  sigaction(SIGFPE, &sa, previous);
  previous = &previous_actions[action_slot(SIGILL)];
  sigaction(SIGILL, &sa, previous);
}

bool& seh_active() {
  return tls_seh_active;
}

}  // namespace rex::platform
