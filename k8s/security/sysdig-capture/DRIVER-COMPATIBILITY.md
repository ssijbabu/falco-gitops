# `sysdig-capture` driver compatibility: findings and root cause

**Status: working, via `--modern-bpf`.** `docker.io/sysdig/sysdig:0.41.4`
captures fine on AKS when started with `sysdig --modern-bpf` and with the
image's entrypoint bypassed. Verified live on an AKS Azure Linux 3.0 node
(kernel `6.6.150.1-1.azl3`, the same kernel as attempt 3 below), with no
kernel headers, no driver build, and no `privileged: true`.

The three attempts recorded further down all failed, and their diagnoses
(GCC flags, glibc/modpost, missing headers) are correct. But every one of
them used the kernel-module or *legacy* eBPF driver. None used the modern
eBPF engine. This file's first version concluded that the
`sysdig` CLI has no CO-RE/BTF support. That was wrong, and it's kept here
so nobody repeats it.

## TL;DR

- sysdig has **three** Linux capture engines, not two:

  | Selected by | Engine | Needs |
  |---|---|---|
  | *(default)* | kernel module (`/dev/scap0`) | exact-kernel `.ko`, prebuilt or compiled against host headers |
  | `SYSDIG_BPF_PROBE` / `--bpf` | legacy eBPF | exact-kernel `.o`, prebuilt or compiled against host headers |
  | `--modern-bpf` | modern eBPF (CO-RE) | kernel BTF (`/sys/kernel/btf/vmlinux`) only |

- `--modern-bpf` is compiled into the shipped 0.41.4 binary
  (`BUILD_SYSDIG_MODERN_BPF` is on by default in `CMakeLists.txt`; the
  flag appears in the image's `sysdig --help`). It calls
  `inspector->open_modern_bpf()` (`userspace/sysdig/utils/sinsp_opener.cpp`).
  This is the same `falcosecurity/libs` (0.21.0) engine that Falco's
  `modern_ebpf` driver uses.
- `SYSDIG_BPF_PROBE` (attempt 1) selects the **legacy** probe
  (`open_bpf(probe)`), so it hit the same compile path as the kernel module.
- The image's `docker-entrypoint.sh` always runs `scap-driver-loader`
  (download or compile a kmod/legacy probe) before `exec "$@"`. Its failure
  isn't fatal (`set -e` is commented out), but it's pointless for modern eBPF
  and floods the logs with misleading build errors. The DaemonSet now sets
  `command: ["/usr/bin/sysdig"]` to skip it.

## Live verification (AKS, Azure Linux 3.0)

Disposable cluster, `eastus`, one `Standard_D2s_v3` node, `--os-sku
AzureLinux`. The node reported `Microsoft Azure Linux 3.0`,
`6.6.150.1-1.azl3`, `containerd://2.2.4`.

- `/sys/kernel/btf/vmlinux` present; `/lib/modules/6.6.150.1-1.azl3/build`
  absent. Neither fact matters to modern eBPF.
- `sysdig --modern-bpf -M 30 -w /data/test.scap` exited 0 with an 86 MB
  file and 1,147,361 events. `sysdig -r` read back host `execve`s, file
  writes and scheduler switches.
- **Reduced capabilities work:** `privileged: false`, `drop: [ALL]`,
  `add: [BPF, PERFMON, SYS_RESOURCE, SYS_PTRACE]`,
  `allowPrivilegeEscalation: false`. That captured about 1M events in 15 s. The
  exact `daemonset.yaml` in this directory was deployed with these settings.
- **`-G 60 -W 10` is a real ring buffer.** It ran 12+ minutes, holding
  exactly 10 files with the oldest one advancing each minute, 0 restarts,
  and a flat ~135 MB on disk (this idle node). With `-G`, libsinsp's
  `sinsp_cycledumper.cpp` removes the oldest file on each rotation.
  `sysdig --help` still says `-G` + `-W` "exits when reaching the limit".
  That text is stale; the process keeps running.
- **…but the ring doesn't survive restarts.** sysdig keeps the list of files
  to delete only in memory. After replacing the pod, all 10 files from the
  previous pod stayed in the hostPath untouched, next to the new pod's
  files. The `capture-cleanup` sidecar (`RETENTION_MINUTES=12`, so it never
  races the live ring) handles those orphans. It was verified removing them
  with all capabilities dropped.

## Other corrections to the first version

- **Default snaplen is 80 bytes, not full buffers** (`-s` in `sysdig
  --help`). Only the first 80 bytes of each read/write/send/recv payload
  are recorded unless `-s` is raised.
- **Host mounts:** `/host/dev`, `/host/boot`, `/host/lib/modules` and
  `/host/usr` were only needed by `scap-driver-loader` and have been
  dropped. `/host/proc` stays (the image sets `HOST_ROOT=/host`), as does
  `hostPID`.

## Requirements going forward

- The node kernel must expose BTF (`/sys/kernel/btf/vmlinux`). Azure Linux 3
  does; the Ubuntu 22.04/24.04 AKS kernels should too (their
  `CONFIG_DEBUG_INFO_BTF` is on), but those two weren't re-tested with
  `--modern-bpf`.
- Container metadata enrichment (`container.id`, image names) wasn't
  evaluated. Raw capture doesn't need it; mounting
  `/run/containerd/containerd.sock` is the thing to try if you want it.

---

# Historical record: the three failed attempts

Everything below is the original investigation, unchanged. Each failure is
real, but it applies only to the kernel-module and legacy-eBPF engines.

## Original test environment

Disposable AKS cluster (`sysdig-capture-aks`, `eastus`, `Standard_D2s_v3`),
one node pool per OS/kernel combination tested, `falco` namespace, the
`sysdig-capture` DaemonSet from this directory (image tag resolved to
`docker.io/sysdig/sysdig:0.41.4`, the current stable multi-arch tag at
time of testing).

## Attempt 1: default AKS node pool (Ubuntu 24.04.5, kernel `6.8.0-1067-azure`)

Kernel module path (the manifest's real default, `driver=module`):

```
* Trying to download a prebuilt scap module from https://download.sysdig.com/scap-drivers/8.1.0%2Bdriver/x86_64/scap_ubuntu-azure_6.8.0-1067-azure_75.ko
curl: (22) The requested URL returned error: 404
Unable to find a prebuilt scap module
* Trying to dkms install scap module with GCC /usr/bin/gcc
...
warning: the compiler differs from the one used to build the kernel
  The kernel was built by: x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
  You are using:           gcc (GCC) 8.5.0 20210514 (Red Hat 8.5.0-28)
...
gcc: error: unrecognized command line option '-ftrivial-auto-var-init=zero'
gcc: error: unrecognized command line option '-fzero-call-used-regs=used-gpr'
...
Unable to load the driver
error opening device /host/dev/scap0: No such file or directory
```

`-ftrivial-auto-var-init=` and `-fzero-call-used-regs=` are kernel
security-hardening flags the *running* kernel's own config selects during
module compilation. They were introduced in GCC 12; this image's GCC 8.5.0
predates them entirely and errors out rather than ignoring them.

Forcing the eBPF driver instead (`SYSDIG_BPF_PROBE` env var set, any value
— see `scap-driver-loader.in:712`) hit the identical GCC-8-vs-flags failure,
since the eBPF compile path uses the same local toolchain.

## Attempt 2: Ubuntu 22.04.5, kernel `5.15.0-1121-azure`

Added a second AKS node pool (`--os-sku Ubuntu2204`) specifically to test
an older kernel, on the theory that an older kernel's own build might use
an older GCC whose flags this image's GCC 8.5.0 could actually satisfy.

Same eBPF compile failure at first (kernel built by GCC 11.4.0, still past
GCC 8.5.0's flag support). Installed `gcc-toolset-12` (GCC 12.2.1) from
UBI8's own public AppStream repo at runtime and prepended it to `PATH` —
`scap-driver-loader` resolves `gcc` via `which gcc`, so it picked up the
newer compiler correctly (confirmed in the logs: `You are using: gcc (GCC)
12.2.1`). This **did** clear the flag-mismatch error. A new, different
failure appeared underneath it:

```
[configure-bpf] Build output for HAS_0__SANITY:
...
  MODPOST /usr/src/scap-8.1.0+driver/bpf/configure/0__SANITY/Module.symvers
scripts/mod/modpost: /lib64/libc.so.6: version `GLIBC_2.33' not found (required by scripts/mod/modpost)
scripts/mod/modpost: /lib64/libc.so.6: version `GLIBC_2.34' not found (required by scripts/mod/modpost)
...
[configure-bpf] Build system is broken, please see above errors
```

`scripts/mod/modpost` is not something compiled locally — it's a prebuilt
ELF binary shipped **by the host's own kernel-headers package**, built
against Ubuntu 22.04's glibc (~2.35). UBI8's glibc (~2.28) can't satisfy
its dynamic-link requirements. No amount of installing a newer GCC fixes
this: the problem isn't compiling C code anymore, it's running a
host-provided binary tool whose ABI requirements exceed what the
container's own base OS provides. This is independent of kernel version —
it would affect any Ubuntu 20.04+ kernel-headers package, since Ubuntu's
own toolchain moved past glibc 2.33/2.34 long ago.

(A second, unrelated probe — `RSS_STAT_ARRAY`, checking for
`mm->rss_stat[0].count` — also failed with a normal source-level
kernel-struct-layout mismatch, `test.c:27:20: error: subscripted value is
not an array, pointer, or vector`. This is expected, harmless
feature-detection behavior — one capability probe failing just means that
kernel feature is compiled out — and not the actual blocker; the fatal one
is the glibc/modpost failure above.)

Root cause confirmed by manually reproducing the exact failing `make -C
/usr/src/scap-8.1.0+driver/bpf` command outside the driver-loader script's
own `> /dev/null` redirect, in a debug pod with the gcc-toolset-12 fix
applied and the same host mounts as the real DaemonSet.

## Attempt 3: Azure Linux 3.0, kernel `6.6.150.1-1.azl3`

Third AKS node pool (`--os-sku AzureLinux`, which resolves to Azure Linux
3.0 — `AzureLinux3` is the same generation, there is no newer "4.0" SKU
available in AKS as of this writing). Different failure again, more
fundamental:

```
* Trying to compile the eBPF probe (scap_azurelinux_6.6.150.1-1.azl3_1.o)
make[1]: *** /lib/modules/6.6.150.1-1.azl3/build: No such file or directory.  Stop.
```

Azure Linux's minimal node image doesn't ship kernel headers on the host
at all (no `/lib/modules/<release>/build` symlink, unlike Ubuntu, which
does). There's nothing to compile against regardless of toolchain —
installing kernel-devel packages on the host isn't something this
DaemonSet can do (out of scope: modifying node OS packages from a pod).
