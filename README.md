# WatusiServiceDiag

Diagnostic-only rootless tweak for WhatsApp/Watusi `ServiceExtension` failures on iOS 16 / Dopamine.

It does **not** modify Jetsam limits. It is designed to run alongside `WatusiJetsamUncap`, `FixWANotifs`, or another memory-limit tweak while diagnosing why `ServiceExtension` disappears.

## What it records

### In `runningboardd`

- Every memory-limit assignment made to WhatsApp's `ServiceExtension` using memorystatus commands 5, 6, and 7.
- The values requested by RunningBoard/the caller.
- A command-8 (`GET_MEMLIMIT_PROPERTIES`) query immediately after each assignment, showing the limits the kernel reports as effective.
- `ServiceExtension` physical footprint, resident size, and lifetime maximum physical footprint sampled every 250 ms while the process exists.
- The last observed footprint when the PID disappears.

Main log:

`/var/mobile/Library/Logs/WatusiServiceDiag.log`

### Inside `ServiceExtension`

The tweak also injects a diagnostic probe into the WhatsApp ServiceExtension. It logs:

- successful diagnostic injection
- Objective-C exception throws
- `abort()`
- `exit()`
- `_exit()`
- `raise()`

These events are written to Apple's unified log under subsystem:

`com.551.watusiservicediag`

Basic event notifications are also relayed to the runningboardd file log.

## How to use

1. Install the rootless DEB.
2. Keep your current Watusi/Jetsam setup unchanged for the test.
3. Perform a **Userspace Reboot**.
4. Reproduce the WhatsApp problem until `ServiceExtension` disappears / incoming messages stop.
5. In NewTerm run:

```sh
su
watusidiag-collect
```

The command prints the path to a report such as:

`/var/mobile/Library/Logs/WatusiServiceDiag-report-20260901-171500.txt`

Send that report for analysis. Also send the matching `ServiceExtension-*.ips` or `JetsamEvent-*.ips` from Settings > Privacy & Security > Analytics & Improvements > Analytics Data if one exists.

## Interpreting the useful lines

Example:

```text
SET cmd=7 pid=123 requested active=24 ... inactive=24 ...
VERIFY after-cmd7 pid=123 active=256 ... inactive=256 ...
MEM pid=123 phys=108.4MB ...
PROCESS DISAPPEARED pid=123 last_phys=109.1MB ...
```

That would prove a 256 MB limit was actually in force and the process died well below it, making a simple per-process Jetsam limit much less likely.

If the file instead shows `VERIFY ... active=24`, the memory-limit tweak did not actually take effect.

## Safety

This package intentionally does not suppress crashes, change memory limits, or prevent iOS from terminating processes. Its job is to observe with minimal behavioral changes.
