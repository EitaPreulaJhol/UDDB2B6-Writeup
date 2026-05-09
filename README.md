# UDDB2B6.sys: Reverse engineering a signed driver with nice primitives.

> A defensive reverse engineering write-up of `UDDB2B6.sys`, a signed Windows kernel driver that exposes physical memory, MSR, I/O port, and PCI configuration primitives to user mode.

## TL;DR:

`UDDB2B6.sys` is a 64-bit Windows kernel driver with a valid Authenticode signature and a broad low-level hardware access surface. Static analysis shows that an Administrator-accessible device interface exposes IOCTLs for:

- Mapping arbitrary physical memory into user mode
- Reading and writing physical memory
- Reading and writing MSRs
- Reading and writing raw I/O ports
- Reading and writing PCI configuration space

The most serious issue is the physical memory mapping path. The driver calls `MmMapIoSpace`, builds an MDL, maps the pages into user mode with `MmMapLockedPagesSpecifyCache`, and returns that user-mode address to the caller. In practical defensive terms, this is the kind of primitive that makes a signed driver useful in Bring Your Own Vulnerable Driver (BYOVD) tradecraft.

No exploit code is provided here. This article is written for defenders, reverse engineers, malware analysts, and anyone building detection or driver-blocking logic.

## Why it's dangerous?

The Windows kernel is designed around strict boundaries between user mode and kernel mode. A driver that intentionally exposes low-level hardware primitives can punch through those boundaries if it does not apply tight access control, strict address validation, and narrow caller authorization.

`UDDB2B6.sys` does not merely expose one risky call. It exposes a collection of primitives that, together, form a powerful kernel interaction surface:

- Physical memory can be mapped into user mode.
- Physical memory can be read or written through short helper IOCTLs.
- MSRs can be read and mostly written.
- Raw I/O ports can be read and written.
- PCI configuration space can be read and written.

The device ACL restricts access to `SYSTEM` and local `Administrators`, but that is not enough for this threat model. BYOVD abuse usually starts after an attacker has already gained elevated user-mode execution. From there, an Administrator-accessible vulnerable driver can become the bridge into kernel tampering.

## Binary profile:

| Property | Value |
|---|---|
| Architecture | x64 / AMD64 (`Machine = 0x8664`) |
| PE format | PE32+ (`Magic = 0x20b`) |
| Subsystem | Native (`1`) |
| Image base | `0x140000000` |
| Entry RVA | `0x1640` |
| Image size | 45,056 bytes |
| Link timestamp | 2024-02-12 09:47:29 UTC |
| File version | `5.0.0.0` |
| Product version | `5.0.0.0` |
| Description | `Low-Level Driver` |
| Debug build | False |
| Private build | True |
| Authenticode status | Valid |
| Signature type | Authenticode |
| OS binary | False |

### PE Sections:

| Section | RVA | Virtual size | Raw offset | Raw size | Characteristics |
|---|---:|---:|---:|---:|---|
| `.text` | `0x1000` | 4,841 | `0x400` | 5,120 | `0x68000020` |
| `.rdata` | `0x3000` | 3,236 | `0x1800` | 3,584 | `0x48000040` |
| `.data` | `0x4000` | 544 | `0x2600` | 512 | `0xc8000040` |
| `.pdata` | `0x5000` | 660 | `0x2800` | 1,024 | `0x48000040` |
| `PAGE` | `0x6000` | 6,535 | `0x2c00` | 6,656 | `0x60000020` |
| `INIT` | `0x8000` | 1,644 | `0x4600` | 2,048 | `0x62000020` |
| `.rsrc` | `0x9000` | 688 | `0x4e00` | 1,024 | `0x42000040` |
| `.reloc` | `0xa000` | 48 | `0x5200` | 512 | `0x42000040` |

## Imports:

| Module | Imports |
|---|---|
| `HAL.dll` | `HalGetBusDataByOffset`, `HalSetBusDataByOffset` |
| `ntoskrnl.exe` | `MmMapIoSpace`, `MmUnmapIoSpace`, `IoAllocateMdl`, `MmBuildMdlForNonPagedPool`, `MmMapLockedPagesSpecifyCache`, `MmUnmapLockedPages`, `IoFreeMdl`, `PsGetCurrentProcessId`, `IoCreateSymbolicLink`, `IoDeleteSymbolicLink`, `IoRegisterShutdownNotification`, `IoUnregisterShutdownNotification`, `ExAllocatePoolWithTag`, `ExFreePoolWithTag`, `ZwOpenKey`, `ZwCreateKey`, `ZwQueryValueKey`, `ZwSetValueKey`, `KeBugCheckEx` |

Notable embedded strings:

```text
Created device: %S
Created link: %S -> %S
Deleted link: %S
Mapped %d bytes at %X to %X
Releasing %d bytes at %X
Driver.pdb
Low-Level Driver
D:P(A;;GA;;;SY)(A;;GA;;;BA)
\Device\%ls
\??\%ls
```

The strings line up cleanly with the recovered control flow: device creation, symbolic link creation, mapping events, unmapping events, and an Administrator/SYSTEM-only security descriptor.

## Recovered function map:

The IDA database contained the renamed symbols used below.

| Address | Function | Role |
|---:|---|---|
| `0x140001590` | `DbgPrint_Stub` | Empty debug logging function |
| `0x1400015A0` | `SafeStringCchVPrintfW` | Bounded wide-string formatter |
| `0x140001640` | `DriverEntry` | Initializes the driver, device, symlink, and dispatch table |
| `0x140001920` | `DispatchCreateClose` | Handles `IRP_MJ_CREATE` and increments handle count |
| `0x140001950` | `DispatchClose` | Handles `IRP_MJ_CLOSE` and decrements handle count |
| `0x140001980` | `IrpSuccess_Stub` | Generic success handler |
| `0x1400019B0` | `DriverUnload` | Deletes symlink/device and frees stored strings |
| `0x140001A60` | `NotImplemented_Stub` | Returns `STATUS_NOT_IMPLEMENTED` |
| `0x140001A90` | `IoctlWriteMsr` | Writes MSRs with a narrow blocklist |
| `0x140001B00` | `IoctlReadMsr` | Reads MSRs |
| `0x140001B50` | `IoctlMapPhysicalMemory` | Maps physical memory into user mode |
| `0x140001CD0` | `DispatchTable` | Main `IRP_MJ_DEVICE_CONTROL` dispatcher |

## Driver initialization:

`DriverEntry` derives the service name from the last component of the registry path, then builds the runtime device and symbolic link names:

```text
\Device\<service_name>
\??\<service_name>
```

Important initialization details:

| Field | Value |
|---|---|
| Device type | `FILE_DEVICE_UNKNOWN` (`0x22`) |
| Characteristics | `FILE_DEVICE_SECURE_OPEN` (`0x100`) |
| Device extension size | `0x2818` bytes |
| Pool tag | `0x76697244` (`DriV` string) |
| Device flag | `DO_BUFFERED_IO` (`0x10`) |
| Shutdown notification | Registered |
| Security descriptor | `D:P(A;;GA;;;SY)(A;;GA;;;BA)` |

The SDDL grants generic-all access to `SYSTEM` and built-in `Administrators`. That blocks ordinary unprivileged callers, but it does not solve the BYOVD problem: elevated malware can still open the device and issue the same IOCTLs as a legitimate administrative tool.

## IOCTL surface:

The main dispatch routine handles 11 IOCTLs:

| IOCTL | Capability | Primitive |
|---:|---|---|
| `0x80006430` | Read I/O port | `__inbyte`, `__inword`, `__indword` |
| `0x80006434` | Write I/O port | `__outbyte`, `__outword`, `__outdword` |
| `0x80006448` | Read MSR | `__readmsr` |
| `0x8000644C` | Write MSR | `__writemsr` |
| `0x8000645C` | Map physical memory | `MmMapIoSpace` + MDL + user-mode mapping |
| `0x80006460` | Unmap physical memory | `MmUnmapLockedPages`, `MmUnmapIoSpace`, `IoFreeMdl` |
| `0x80006494` | Get handle count | Device extension counter |
| `0x80006498` | Read physical memory | Transient `MmMapIoSpace` read |
| `0x8000649C` | Write physical memory | Transient `MmMapIoSpace` write |
| `0x800064A0` | Read PCI config | `HalGetBusDataByOffset` |
| `0x800064A4` | Write PCI config | `HalSetBusDataByOffset` |

The device uses `DO_BUFFERED_IO`, so these requests operate through the IRP system buffer. The dispatcher relies mostly on `InputBufferLength` and `OutputBufferLength` checks, then reads and writes fields in that shared buffer in place.

### Recovered IOCTL contracts:

| IOCTL | Input length | Output length | Notes |
|---:|---:|---:|---|
| `0x80006430` | 2 | 1, 2, or 4 | Input is a 16-bit I/O port. Output width selects byte/word/dword read. |
| `0x80006434` | 5, 6, or 8 | 0 | Input is a 16-bit I/O port followed by byte/word/dword data. |
| `0x80006448` | 4 | 8 | Input is an MSR index. Output is the 64-bit MSR value. |
| `0x8000644C` | 12 | 0 | Input is a 32-bit MSR index followed by a 64-bit value. |
| `0x8000645C` | 12 | 4 or 8 | Input is physical address plus size. Output is the mapped user VA, with only the low 32 bits returned when output length is 4. |
| `0x80006460` | 4 or 8 | 0 | Input is the user VA returned by the map call. |
| `0x80006494` | 0 | 4 | Returns the driver's current create-handle counter. |
| `0x80006498` | 8 | 1, 2, 4, or 8 | Input is a physical address. Output is the value read from transiently mapped memory. |
| `0x8000649C` | 9, 10, 12, or 16 | 0 | Input is a physical address followed by byte/word/dword/qword data. |
| `0x800064A0` | 8 | non-zero caller-selected length | Reads PCI configuration data using bus/device/function/offset fields packed into the input qword. |
| `0x800064A4` | 9, 10, or 12 | 0 | Writes 1, 2, or 4 bytes to PCI configuration space. |

The dispatcher completes successful requests with `IoStatus.Information` set to the requested output length, not necessarily a separately calculated byte count. That is mostly consistent with the fixed-width helpers, but it is another sign that this was built as a permissive utility interface rather than a hardened kernel boundary.

## Finding: Physical memory mapping into user mode:

The most important function is `IoctlMapPhysicalMemory`.

At a high level, it does the following:

1. Receives a physical address and size from the caller.
2. Maps the physical address range into kernel virtual address space with `MmMapIoSpace`.
3. Allocates an MDL for that mapping with `IoAllocateMdl`.
4. Builds the MDL with `MmBuildMdlForNonPagedPool`.
5. Maps the MDL into user mode with `MmMapLockedPagesSpecifyCache`.
6. Returns the user-mode virtual address to the caller.
7. Stores mapping metadata in a 256-entry table in the device extension.

The key sequence is:

```text
MmMapIoSpace(...)
IoAllocateMdl(...)
MmBuildMdlForNonPagedPool(...)
MmMapLockedPagesSpecifyCache(..., AccessMode = UserMode, ...)
```

The mapping table stores:

| Stored field | Purpose |
|---|---|
| Mapping size | Used when unmapping |
| Kernel VA | Result of `MmMapIoSpace` |
| User VA | Result of `MmMapLockedPagesSpecifyCache` |
| MDL pointer | Used by `MmUnmapLockedPages` and `IoFreeMdl` |
| Caller PID | Checked during unmap |

The mapping table has 256 entries. Each entry is 40 bytes, and the entry is considered occupied when the stored mapping size is non-zero. The unmap path searches for both the returned user VA and the caller PID before releasing the entry, which prevents one process from using the unmap IOCTL to release another process's recorded mapping. It does not reduce the exposure created by the original map primitive.

### Impact:

This gives an elevated user-mode caller a direct window into physical memory. Depending on the target system and memory layout, that may allow tampering with kernel code, kernel data, page tables, security product state, credential-adjacent memory, or other sensitive regions.

## Finding: Direct physical Read/Write helpers:

The driver also exposes short physical memory read/write operations:

| IOCTL | Behavior |
|---:|---|
| `0x80006498` | Accepts an 8-byte physical address, maps it, reads 1, 2, 4, or 8 bytes, then unmaps |
| `0x8000649C` | Accepts a physical address plus value, maps it, writes 1, 2, 4, or 8 bytes, then unmaps |

These are smaller than the persistent mapping primitive, but they are still highly sensitive. They provide targeted physical memory access without requiring the caller to manage a long-lived mapping table entry.

The helpers validate transfer width but do not validate that the physical address belongs to a safe device MMIO range. Both paths use `MmNonCached`.

## Finding: MSR Writes are only narrowly blocked:

`IoctlWriteMsr` implements a small blocklist:

| Blocked range | Common meaning |
|---|---|
| `0xC0000000` through `0xC0000002` | Syscall-related MSRs |
| `0x174` through `0x176` | SYSENTER-related MSRs |

Everything else is allowed. A small MSR denylist is not a strong defense, especially in a driver that also exposes arbitrary physical memory access.

The read side has no comparable denylist: any 32-bit MSR index supplied in the 4-byte input buffer is passed to `__readmsr`, with the 64-bit result written back to the caller's buffer.

## Finding: Raw port and PCI access are exposed:

The I/O port helpers expose direct `__in*` and `__out*` instructions for byte, word, and dword transfers. The read path takes a 16-bit port and uses the output length as the transfer width. The write path accepts compact 5, 6, or 8 byte structures containing the port and value.

The PCI helpers call `HalGetBusDataByOffset` and `HalSetBusDataByOffset` with `PCIConfiguration`. The packed 64-bit request value is decoded as:

| Bits / field | Use |
|---|---|
| Low byte | Bus number |
| Bits 8-12 | Device number |
| Bits 16-18 | Function number |
| High dword | Configuration-space offset |

For defenders, these are useful secondary signals. Even if physical memory access is the highest-impact primitive, raw port and PCI configuration access make this driver broader than a single-purpose memory mapper.

## Finding: Administrator ACL is not tight:

The device security descriptor is:

```text
D:P(A;;GA;;;SY)(A;;GA;;;BA)
```

That grants full access to `SYSTEM` and local `Administrators`. This may look reasonable for a hardware utility driver, but it is weak in a BYOVD threat model. Once malware has elevated execution, it can interact with the driver as an Administrator and use its kernel-facing primitives.

## Finding: Logging calls exist, but logging is gone:

The code still contains calls around useful lifecycle events:

- Device creation
- Symbolic link creation
- Symbolic link deletion
- Physical memory mapping
- Physical memory unmapping

But `DbgPrint_Stub` is empty. As a result, the driver has strings that describe sensitive behavior, yet those messages are not emitted at runtime.

## Finding: Mapping error paths can leak resources:

The mapping logic has failure paths that do not appear to clean up all previously allocated or mapped resources:

- If `IoAllocateMdl` fails after `MmMapIoSpace` succeeds, the mapped I/O space is not visibly unmapped before returning failure.
- If all 256 mapping slots are occupied, the function can reach the full-table failure path after creating a new mapping and MDL.
- No strict upper bound on requested mapping size is apparent in the decompiled output.

This is secondary to the security exposure, but it matters for stability. Repeated failure-path triggering or large mappings could create resource pressure.

## Attack surface summary:

An elevated caller can reach the driver through its DOS device symbolic link and issue `DeviceIoControl` requests. The highest-risk path is:

1. Open the device as Administrator.
2. Use `0x8000645C` to map physical memory into user mode.
3. Inspect or modify sensitive memory through the returned user-mode VA.
4. Optionally use the short physical read/write, MSR, port I/O, or PCI config IOCTLs for narrower operations.

The driver does not appear to restrict IOCTLs to a trusted client binary, does not authenticate the caller beyond the device ACL, and does not validate that requested physical addresses are safe to expose.
