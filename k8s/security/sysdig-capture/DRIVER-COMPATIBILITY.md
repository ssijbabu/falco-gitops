# `sysdig-capture` driver compatibility: findings and root cause

**Status: blocked.** `docker.io/sysdig/sysdig:0.41.4` cannot load its kernel
capture driver (kernel module or eBPF probe) on any of the three AKS node
OS/kernel combinations tested. This is a structural limitation of the
published image, not something fixable via node selection, `nodeSelector`,
or pod-spec tuning. Kept here as the record of what was tried and why, so
the next person (or the next AI session) doesn't repeat the same three
attempts before finding this.

## TL;DR

- `sysdig`'s driver loader (`scap-driver-loader`) tries, in order: download a
  prebuilt driver for the exact running kernel release → compile one
  locally against the host's kernel headers. Both paths failed on all
  three node OS options AKS currently offers.
- No prebuilt driver/eBPF probe exists for *any* of the three exact kernel
  releases tested — expected, since AKS patches kernels far more often
  than `sysdig`'s driver-build catalog is updated.
- Local compilation fails for a **different reason on each OS**, but the
  common thread is the same: `sysdig/sysdig:0.41.4`'s base image
  (`registry.access.redhat.com/ubi8/ubi`, i.e. RHEL 8) has an old
  toolchain (GCC 8.5.0, glibc ~2.28) that can't build against modern,
  actively-patched kernels' own build requirements.
- This CLI (`draios/sysdig`) has **no CO-RE/BTF/libbpf support** — it only
  supports the legacy "compile an object file matching this exact kernel"
  model. Falco's own `modern_ebpf` driver (from the actively-maintained
  `falcosecurity/libs`, already the default in `security/falco/falco.yaml`)
  is CO-RE-based and doesn't have this problem — see "What would actually
  fix this" below.

## Test environment

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

## Why this isn't a node-selection problem

Three different OS families, three different kernel series (6.8.x, 5.15.x,
6.6.x), three different failure *mechanisms* (compiler-flag mismatch,
glibc ABI mismatch, missing host headers entirely) — all downstream of the
same root cause: `sysdig/sysdig:0.41.4`'s RHEL-8-based image trying to
build kernel-matched artifacts against hosts whose own toolchains and
packaging have moved well past what that base image ships. No AKS node OS
option currently available sidesteps this.

## What would actually fix this

1. **A custom `sysdig` image on a modern base** (current-generation
   Ubuntu/Debian, matching glibc/GCC to what current kernels actually
   need) would likely clear all three failures above. It would *not* fix
   the underlying fragility, though: this tool's driver model requires an
   exact kernel-release match (prebuilt or freshly compiled) with no
   portability layer, so it would need re-verifying against every AKS node
   image update going forward — a real ongoing maintenance cost.
2. **Use a CO-RE (Compile Once – Run Everywhere) driver instead.**
   `falcosecurity/libs`' `modern_ebpf` driver — the actively maintained
   project, and already the *default* Falco itself uses in this repo's own
   `security/falco/falco.yaml` — resolves kernel struct layouts at load
   time via BTF, not at build time via local compilation against exact
   headers. It doesn't have any of the three failure modes above, and
   doesn't need re-verifying on every kernel patch. If the underlying goal
   (an always-on rolling capture buffer, not just rule-triggered) is still
   wanted, this is the direction to build it in, not a patch on top of the
   legacy `sysdig` CLI.

## What still works

Falco's own rule-triggered `capture:` feature (`security/falco/falco.yaml`
+ a rule's `capture: true`) uses the `modern_ebpf` driver already, via the
same falco-operator-managed Falco DaemonSet this repo deploys for
detection. It doesn't share any of `sysdig-capture`'s problems. See
`k8s/README.md` for how that's verified live.
