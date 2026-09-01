// WatusiServiceDiag 1.0.0
// Made by 551
//
// Diagnostic-only tweak. It DOES NOT change Jetsam limits.
//
// runningboardd side:
//   - logs every WhatsApp ServiceExtension memlimit SET request (commands 5/6/7)
//   - immediately queries command 8 to verify the kernel's effective active/inactive limits
//   - samples the target process with proc_pid_rusage(RUSAGE_INFO_V4), including physical footprint
//   - records when the process disappears and its last observed footprint
//
// ServiceExtension side:
//   - confirms injection
//   - logs Objective-C throws and common deliberate termination paths
//   - leaves the original behavior intact

#import <Foundation/Foundation.h>
#import <substrate.h>
#import <os/log.h>

#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <errno.h>
#include <libproc.h>
#include <notify.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>

#define PROC_PIDPATHINFO_MAXSIZE 4096

#define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK 5
#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT      6
#define MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES    7
#define MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES    8

#define WSD_LOG_PATH "/var/mobile/Library/Logs/WatusiServiceDiag.log"
#define WSD_NOTIFY_LOADED    "com.551.watusiservicediag.extension.loaded"
#define WSD_NOTIFY_EXCEPTION "com.551.watusiservicediag.extension.exception"
#define WSD_NOTIFY_ABORT     "com.551.watusiservicediag.extension.abort"
#define WSD_NOTIFY_EXIT      "com.551.watusiservicediag.extension.exit"
#define WSD_NOTIFY__EXIT     "com.551.watusiservicediag.extension._exit"
#define WSD_NOTIFY_RAISE     "com.551.watusiservicediag.extension.raise"

typedef struct memorystatus_memlimit_properties {
    int32_t  memlimit_active;
    uint32_t memlimit_active_attr;
    int32_t  memlimit_inactive;
    uint32_t memlimit_inactive_attr;
} memorystatus_memlimit_properties_t;

extern int memorystatus_control(uint32_t command,
                                int32_t pid,
                                uint32_t flags,
                                void *buffer,
                                size_t buffersize);

static int (*orig_memorystatus_control)(uint32_t, int32_t, uint32_t, void *, size_t);
static void (*orig_abort)(void);
static void (*orig_exit)(int);
static void (*orig__exit)(int);
static int  (*orig_raise)(int);
static void (*orig_objc_exception_throw)(id);

static os_log_t wsd_oslog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create("com.551.watusiservicediag", "diag");
    });
    return log;
}

static const char *wsd_basename(const char *path) {
    if (!path) return NULL;
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static bool wsd_current_executable_is(const char *name) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) != 0) return false;
    const char *base = wsd_basename(path);
    return base && strcmp(base, name) == 0;
}

static bool wsd_is_whatsapp_service_path(const char *path) {
    if (!path) return false;
    if (!strstr(path, "/PlugIns/ServiceExtension.appex/ServiceExtension")) return false;

    if (strstr(path, "/WhatsApp.app/") ||
        strstr(path, "/WhatsApp Business.app/") ||
        strstr(path, "/Watusi.app/")) {
        return true;
    }

    const char *appext = strstr(path, ".app/");
    if (!appext) return false;
    const char *start = appext;
    while (start > path && start[-1] != '/') start--;
    size_t len = (size_t)(appext - start);

    for (size_t i = 0; i + 8 <= len; i++) {
        if (memcmp(start + i, "WhatsApp", 8) == 0) return true;
    }
    for (size_t i = 0; i + 6 <= len; i++) {
        if (memcmp(start + i, "Watusi", 6) == 0) return true;
    }
    return false;
}

static bool wsd_target_pid(int32_t pid, char path[PROC_PIDPATHINFO_MAXSIZE]) {
    if (pid < 2) return false;
    memset(path, 0, PROC_PIDPATHINFO_MAXSIZE);
    int n = proc_pidpath(pid, path, PROC_PIDPATHINFO_MAXSIZE);
    return n > 0 && wsd_is_whatsapp_service_path(path);
}

static dispatch_queue_t g_log_queue;

static void wsd_log_line_sync(const char *fmt, ...) {
    if (!fmt) return;

    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char stamp[64];
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv);

    int fd = open(WSD_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        dprintf(fd, "[%s] %s\n", stamp, msg);
        fsync(fd);
        close(fd);
    }

    os_log(wsd_oslog(), "%{public}s", msg);
}

static void wsd_log_line(const char *fmt, ...) {
    if (!fmt) return;
    char msg[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (!g_log_queue) {
        wsd_log_line_sync("%s", msg);
        return;
    }

    char *copy = strdup(msg);
    if (!copy) return;
    dispatch_async(g_log_queue, ^{
        wsd_log_line_sync("%s", copy);
        free(copy);
    });
}

typedef struct {
    int32_t pid;
    uint64_t last_footprint;
    uint64_t last_max_footprint;
    uint64_t last_log_ns;
    bool active;
} wsd_monitor_t;

static wsd_monitor_t g_monitor = {0};
static dispatch_queue_t g_monitor_queue;
static dispatch_source_t g_monitor_timer;

static uint64_t wsd_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double wsd_mb(uint64_t bytes) {
    return (double)bytes / (1024.0 * 1024.0);
}

static void wsd_monitor_tick(void) {
    if (!g_monitor.active || g_monitor.pid < 2) return;

    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int n = proc_pidpath(g_monitor.pid, path, sizeof(path));
    if (n <= 0 || !wsd_is_whatsapp_service_path(path)) {
        wsd_log_line("PROCESS DISAPPEARED pid=%d last_phys=%.2fMB last_lifetime_max=%.2fMB",
                     g_monitor.pid,
                     wsd_mb(g_monitor.last_footprint),
                     wsd_mb(g_monitor.last_max_footprint));
        g_monitor.active = false;
        return;
    }

    struct rusage_info_v4 ri;
    memset(&ri, 0, sizeof(ri));
    int rv = proc_pid_rusage(g_monitor.pid, RUSAGE_INFO_V4, (rusage_info_t *)&ri);
    if (rv != 0) return;

    uint64_t now = wsd_now_ns();
    uint64_t cur = ri.ri_phys_footprint;
    uint64_t max = ri.ri_lifetime_max_phys_footprint;
    uint64_t delta = cur > g_monitor.last_footprint
        ? cur - g_monitor.last_footprint
        : g_monitor.last_footprint - cur;

    if (g_monitor.last_log_ns == 0 || delta >= (1ULL << 20) || now - g_monitor.last_log_ns >= 2000000000ULL) {
        wsd_log_line("MEM pid=%d phys=%.2fMB resident=%.2fMB lifetime_max=%.2fMB",
                     g_monitor.pid,
                     wsd_mb(ri.ri_phys_footprint),
                     wsd_mb(ri.ri_resident_size),
                     wsd_mb(ri.ri_lifetime_max_phys_footprint));
        g_monitor.last_log_ns = now;
    }

    g_monitor.last_footprint = cur;
    g_monitor.last_max_footprint = max;
}

static void wsd_start_monitor(int32_t pid) {
    if (pid < 2) return;
    dispatch_async(g_monitor_queue, ^{
        if (g_monitor.active && g_monitor.pid == pid) return;

        g_monitor.pid = pid;
        g_monitor.last_footprint = 0;
        g_monitor.last_max_footprint = 0;
        g_monitor.last_log_ns = 0;
        g_monitor.active = true;
        wsd_log_line("MONITOR START pid=%d", pid);
    });
}

static void wsd_setup_monitor_timer(void) {
    g_monitor_queue = dispatch_queue_create("com.551.watusiservicediag.monitor", DISPATCH_QUEUE_SERIAL);
    g_monitor_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, g_monitor_queue);
    dispatch_source_set_timer(g_monitor_timer,
                              dispatch_time(DISPATCH_TIME_NOW, 0),
                              250ULL * NSEC_PER_MSEC,
                              50ULL * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(g_monitor_timer, ^{
        wsd_monitor_tick();
    });
    dispatch_resume(g_monitor_timer);
}

static void wsd_verify_limit(int32_t pid, const char *context) {
    memorystatus_memlimit_properties_t got;
    memset(&got, 0, sizeof(got));
    int grv = orig_memorystatus_control(MEMORYSTATUS_CMD_GET_MEMLIMIT_PROPERTIES,
                                       pid, 0, &got, sizeof(got));
    if (grv == 0) {
        wsd_log_line("VERIFY %s pid=%d active=%d attr=0x%x inactive=%d attr=0x%x",
                     context, pid,
                     got.memlimit_active, got.memlimit_active_attr,
                     got.memlimit_inactive, got.memlimit_inactive_attr);
    } else {
        wsd_log_line("VERIFY FAILED %s pid=%d rv=%d errno=%d", context, pid, grv, errno);
    }
}

static int wsd_hooked_memorystatus_control(uint32_t command,
                                           int32_t pid,
                                           uint32_t flags,
                                           void *buffer,
                                           size_t buffersize) {
    bool setCmd = command == MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK ||
                  command == MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT ||
                  command == MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES;

    if (!setCmd) {
        return orig_memorystatus_control(command, pid, flags, buffer, buffersize);
    }

    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (!wsd_target_pid(pid, path)) {
        return orig_memorystatus_control(command, pid, flags, buffer, buffersize);
    }

    wsd_start_monitor(pid);

    if (command == MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES &&
        buffer && buffersize == sizeof(memorystatus_memlimit_properties_t)) {
        memorystatus_memlimit_properties_t req = *(memorystatus_memlimit_properties_t *)buffer;
        wsd_log_line("SET cmd=7 pid=%d requested active=%d attr=0x%x inactive=%d attr=0x%x path=%s",
                     pid,
                     req.memlimit_active, req.memlimit_active_attr,
                     req.memlimit_inactive, req.memlimit_inactive_attr,
                     path);

        int rv = orig_memorystatus_control(command, pid, flags, buffer, buffersize);
        wsd_log_line("SET RESULT cmd=7 pid=%d rv=%d errno=%d", pid, rv, errno);
        wsd_verify_limit(pid, "after-cmd7");
        return rv;
    }

    if (command == MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES) {
        wsd_log_line("SET cmd=7 pid=%d unexpected buffer=%p size=%lu path=%s",
                     pid, buffer, (unsigned long)buffersize, path);
        int rv = orig_memorystatus_control(command, pid, flags, buffer, buffersize);
        wsd_verify_limit(pid, "after-cmd7-unknown-layout");
        return rv;
    }

    wsd_log_line("SET cmd=%u pid=%d requested_limit(flags-as-int32)=%d path=%s",
                 command, pid, (int32_t)flags, path);
    int rv = orig_memorystatus_control(command, pid, flags, buffer, buffersize);
    wsd_log_line("SET RESULT cmd=%u pid=%d rv=%d errno=%d", command, pid, rv, errno);
    wsd_verify_limit(pid, command == MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK
                          ? "after-cmd5" : "after-cmd6");
    return rv;
}

static void wsd_register_extension_notifications(void) {
    struct {
        const char *name;
        const char *label;
    } entries[] = {
        { WSD_NOTIFY_LOADED,    "EXTENSION INJECTION CONFIRMED" },
        { WSD_NOTIFY_EXCEPTION, "EXTENSION objc_exception_throw observed" },
        { WSD_NOTIFY_ABORT,     "EXTENSION abort() called" },
        { WSD_NOTIFY_EXIT,      "EXTENSION exit() called" },
        { WSD_NOTIFY__EXIT,     "EXTENSION _exit() called" },
        { WSD_NOTIFY_RAISE,     "EXTENSION raise() called" },
    };

    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        int token = 0;
        const char *name = entries[i].name;
        const char *label = entries[i].label;
        notify_register_dispatch(name, &token, g_log_queue, ^(int t) {
            (void)t;
            wsd_log_line_sync("%s", label);
        });
    }
}

static void wsd_init_runningboardd(void) {
    g_log_queue = dispatch_queue_create("com.551.watusiservicediag.log", DISPATCH_QUEUE_SERIAL);
    wsd_log_line_sync("============================================================");
    wsd_log_line_sync("WatusiServiceDiag 1.0.0 loaded in runningboardd pid=%d", getpid());
    wsd_log_line_sync("Diagnostic only: memory limits are NOT modified by this tweak");

    wsd_setup_monitor_timer();
    wsd_register_extension_notifications();

    MSHookFunction((void *)memorystatus_control,
                   (void *)wsd_hooked_memorystatus_control,
                   (void **)&orig_memorystatus_control);
    wsd_log_line_sync("memorystatus_control hook installed");
}

static bool wsd_am_target_extension(void) {
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int n = proc_pidpath(getpid(), path, sizeof(path));
    return n > 0 && wsd_is_whatsapp_service_path(path);
}

static void wsd_ext_log(const char *fmt, ...) {
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    os_log(wsd_oslog(), "ServiceExtension pid=%d %{public}s", getpid(), msg);
}

static void wsd_hook_abort(void) {
    wsd_ext_log("abort() CALLED");
    notify_post(WSD_NOTIFY_ABORT);
    orig_abort();
    __builtin_unreachable();
}

static void wsd_hook_exit(int status) {
    wsd_ext_log("exit(%d) CALLED", status);
    notify_post(WSD_NOTIFY_EXIT);
    orig_exit(status);
    __builtin_unreachable();
}

static void wsd_hook__exit(int status) {
    wsd_ext_log("_exit(%d) CALLED", status);
    notify_post(WSD_NOTIFY__EXIT);
    orig__exit(status);
    __builtin_unreachable();
}

static int wsd_hook_raise(int sig) {
    wsd_ext_log("raise(%d) CALLED", sig);
    notify_post(WSD_NOTIFY_RAISE);
    return orig_raise(sig);
}

static void wsd_hook_objc_exception_throw(id obj) {
    @autoreleasepool {
        if ([obj isKindOfClass:[NSException class]]) {
            NSException *e = (NSException *)obj;
            wsd_ext_log("objc_exception_throw name=%s reason=%s",
                        e.name.UTF8String ?: "(null)",
                        e.reason.UTF8String ?: "(null)");
        } else {
            wsd_ext_log("objc_exception_throw objectClass=%s",
                        NSStringFromClass([obj class]).UTF8String ?: "(unknown)");
        }
        notify_post(WSD_NOTIFY_EXCEPTION);
    }
    orig_objc_exception_throw(obj);
    __builtin_unreachable();
}

static void wsd_init_service_extension(void) {
    if (!wsd_am_target_extension()) return;

    wsd_ext_log("DIAGNOSTIC INJECTION LOADED");
    notify_post(WSD_NOTIFY_LOADED);

    void *p = NULL;

    p = dlsym(RTLD_DEFAULT, "abort");
    if (p) MSHookFunction(p, (void *)wsd_hook_abort, (void **)&orig_abort);

    p = dlsym(RTLD_DEFAULT, "exit");
    if (p) MSHookFunction(p, (void *)wsd_hook_exit, (void **)&orig_exit);

    p = dlsym(RTLD_DEFAULT, "_exit");
    if (p) MSHookFunction(p, (void *)wsd_hook__exit, (void **)&orig__exit);

    p = dlsym(RTLD_DEFAULT, "raise");
    if (p) MSHookFunction(p, (void *)wsd_hook_raise, (void **)&orig_raise);

    p = dlsym(RTLD_DEFAULT, "objc_exception_throw");
    if (p) MSHookFunction(p, (void *)wsd_hook_objc_exception_throw,
                          (void **)&orig_objc_exception_throw);

    wsd_ext_log("termination/exception probes installed");
}

%ctor {
    @autoreleasepool {
        if (wsd_current_executable_is("runningboardd")) {
            wsd_init_runningboardd();
            return;
        }

        if (wsd_current_executable_is("ServiceExtension")) {
            wsd_init_service_extension();
            return;
        }
    }
}
