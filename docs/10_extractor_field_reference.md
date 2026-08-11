# MemFlow – Extractor Field Reference

> **Document version:** 1.0 — 2026-03-10  
> **Scope:** Every field produced by every extractor plugin in `extractors/`.

---

## How to Read This Document

Each extractor section lists:
- **Output file** – the CSV written to `<case>/csv/`
- **Source** – where data comes from (`api` = MemProcFS Python API, `vfs` = VFS text file, `forensic_csv` = MemProcFS pre-built CSV at `/forensic/csv/`)
- **Field table** – column name, type, and full description

Blank values in any field mean the kernel object did not expose that attribute (common with system/protected processes).

---

## 1. Processes — `process.csv`

**Extractor:** `ProcessesExtractor` | **Source:** `forensic_csv` (reads existing `process.csv` under the MemProcFS tree)

One row per running process found in memory at snapshot time.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | **Process ID.** Unique numeric identifier assigned by the kernel to this process. 0 = System Idle Process, 4 = System. |
| `ppid` | integer | **Parent Process ID.** PID of the process that spawned this one. Used to reconstruct the process tree. May be stale if the parent has already exited. |
| `pppid` | integer | **Grandparent Process ID.** PID of the parent's parent, resolved at extraction time from the in-memory process list. Empty if the parent is no longer in memory. |
| `name` | string | **Image name.** Short executable name as stored in the EPROCESS structure (max 15 chars on Windows, e.g. `explorer.exe`). May be truncated — use `path` for the full name. |
| `parent_name` | string | **Parent image name.** `name` field of the process whose PID matches `ppid`, looked up in the same snapshot. Empty if the parent has exited. |
| `grandparent_name` | string | **Grandparent image name.** `name` field of the process whose PID matches `pppid`. Useful for detecting unusual parent chains (e.g. `cmd.exe` spawned by `winword.exe`). |
| `path` | string | **Full executable path.** Resolved from `UserPath`, else `KernelPath`, else `Path` / `path` on the source row. |
| `user` | string | **Security Identifier (SID).** Windows SID string of the token owner (e.g. `S-1-5-18` = SYSTEM, `S-1-5-21-…` = domain/local user). |
| `username` | string | **Human-readable username.** Resolved account name corresponding to `user` (e.g. `NT AUTHORITY\SYSTEM`, `DESKTOP-XYZ\alice`). May be empty when resolution fails. |
| `cmdline` | string | **Full command line.** The complete command string used to launch this process, including executable path and all arguments (e.g. `"C:\Windows\system32\svchost.exe -k netsvcs -p"`). |
| `state` | string | **Process state.** Numeric or symbolic kernel state of the EPROCESS object. Common values: `0` = active, `1` = exiting, `2` = zombie. |
| `create_time` | datetime | **Creation timestamp.** When the process was created, derived from `EPROCESS.CreateTime` (Windows FILETIME). Format: ISO-like string from MemProcFS. |
| `exit_time` | datetime | **Exit timestamp.** When the process exited, derived from `EPROCESS.ExitTime`. Blank if the process is still running at snapshot time. |
| `wow64` | boolean | **WoW64 flag.** `True` if this is a 32-bit process running under the Windows-on-Windows 64-bit (WoW64) subsystem on a 64-bit OS. Important for DLL injection and shellcode analysis. |

**Forensic use cases:**
- Detect orphan processes (valid `pid`, missing `parent_name`).
- Flag `wow64=True` processes in unusual locations (common malware staging trick).
- Correlate `create_time` / `exit_time` with network activity in `net.csv`.

---

## 2. Network Connections — `net.csv`

**Extractor:** `NetstatExtractor` | **Source:** `forensic_csv` (reads `forensic/csv/net.csv` when present) with **fallback** to `vfs` (`/sys/net/netstat.txt`)

One row per network socket or connection visible in kernel memory.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | **Owning Process ID.** The PID of the process that owns this socket. Cross-reference with `process.csv` for process context. |
| `process_name` | string | **Process image name.** Resolved from the live process list at extraction time. Blank if the PID no longer has a matching process. |
| `protocol` | string | **Network protocol.** One of `TCP`, `UDP`, `TCPv6`, `UDPv6`. |
| `state` | string | **Connection state.** TCP state machine value: `LISTEN`, `ESTABLISHED`, `CLOSE_WAIT`, `TIME_WAIT`, `SYN_SENT`, `FIN_WAIT1`, `FIN_WAIT2`, etc. UDP sockets show `*` or blank (stateless). |
| `src-addr` | string | **Local IP address.** The local endpoint IP. `0.0.0.0` or `::` means the socket is bound to all interfaces. `127.0.0.1` / `::1` = loopback only. |
| `src-port` | integer | **Local port number.** The port this process is bound to. Ephemeral client ports are typically `49152–65535`. Well-known service ports are `0–1023`. |
| `dst-addr` | string | **Remote IP address.** The peer IP the socket is connected to. `0.0.0.0` / `*` = not yet connected (LISTEN state). |
| `dst-port` | integer | **Remote port number.** The peer port. `0` or `*` for listening/unconnected sockets. |

**Forensic use cases:**
- Identify C2 connections: look for uncommon processes (`name` not in a known-good baseline) with `ESTABLISHED` connections to external IPs.
- Detect lateral movement: internal `dst-addr` ranges combined with unusual `process_name`.
- Map listening services: `state=LISTEN` + `src-addr=0.0.0.0` = publicly reachable.

---

## 3. Loaded DLLs — `dlls.csv`

**Extractor:** `DllsExtractor` | **Source:** `forensic_csv` (reads `modules.csv` first, then `dlls.csv` if needed) with optional dump PE enrichment for entry and checksum fields

One row per DLL loaded in each process's virtual address space.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | **Process ID.** PID of the process that has this module mapped. |
| `process_name` | string | **Process image name.** Short name of the owning process. |
| `module_name` | string | **DLL short name.** Filename as seen in the PEB loader list (e.g. `ntdll.dll`, `kernel32.dll`). May include MemProcFS type prefixes such as `_NOTLINKED-` or `_DATA-`. |
| `module_path` | string | **Full on-disk path.** From `Path` when set; otherwise `KernelPath` (e.g. `\SystemRoot\…`). Empty when the module is not backed by a file (e.g. reflectively loaded shellcode). |
| `base_address` | hex | **Load base address.** Virtual memory address where the DLL's first byte is mapped (`Start` in MemProcFS `modules.csv`). Changes across dumps due to ASLR. |
| `size` | integer | **Mapped size (bytes).** Size of the DLL's virtual memory mapping. Different from the on-disk file size due to section alignment. |
| `entry_point` | hex | **Absolute entry VA.** Filled from CSV `Entry` when present; otherwise from dump enrichment (`mod.entry` or `base_address + entry_point_rva`). Existing non-empty values are never overwritten. |
| `entry_point_rva` | hex | **PE entry offset from module base** (`AddressOfEntryPoint`). Stable for the same image across dumps. Filled from dump PE header when empty; not in typical MemProcFS `modules.csv`. |
| `is_wow64` | boolean | **WoW64 context.** `True` if this module is mapped inside a 32-bit (WoW64) process. Affects address interpretation (32-bit vs 64-bit pointers). |
| `module_type` | string | **Derived from MemProcFS `Name` prefixes** (case-insensitive; optional `_64-` Wow64 strip first): `_DATA-` → `DATA`, `_NOTLINKED-` → `NOTLINKED`, `_INJECTED-` → `INJECTED`, `_NA-` → `NA`, else `NORMAL`. Existing CSV `module_type` values are preserved. |
| `pe_timedatestamp` | integer | **PE compile timestamp** (decimal Unix seconds from COFF `TimeDateStamp`). Filled from dump PE enrichment when empty; `0` is valid and written. Existing non-empty CSV values are never overwritten. |
| `pe_checksum` | integer | **PE optional header checksum** (decimal). Filled from dump PE enrichment when empty; `0` is valid and written. Existing non-empty CSV values are never overwritten. |

**Dump PE enrichment:** when `run_extract` passes `--dump-path`, the dlls extractor opens the dump via the `memprocfs` Python package, reads mapped PE headers for PIDs present in the CSV, and fills empty `entry_point_rva` / `entry_point` / `pe_timedatestamp` / `pe_checksum`. If `memprocfs` is missing or enrichment fails, CSV output is still written; those fields stay empty. Without a dump path, behavior is CSV-only (plus `module_type` from Name prefixes).

**Forensic use cases:**
- Find reflectively-loaded DLLs: `module_path` is empty but a mapping exists at `base_address`.
- Detect DLL hijacking: same `module_name` loaded from an unexpected `module_path`.
- Flag unusual loader state via `module_type` (`NOTLINKED`, `INJECTED`, `DATA`).
- Compare the same binary across dumps via `entry_point_rva` (offset stable; absolute `entry_point` moves with ASLR).

---

## 4. Kernel Modules — `modules.csv`

**Extractor:** `ModulesExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/modules.csv`)

System-wide list of loaded kernel and user-mode modules as enumerated by MemProcFS. This is a **pass-through copy** — fields are defined by MemProcFS and may vary with its version.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | Process ID owning this module (0 = kernel, 4 = System). |
| `ppid` | integer | Parent PID of the owning process. |
| `name` | string | Module short filename. |
| `path` | string | Full on-disk path to the module image. |
| `base` | hex | Virtual base address of the module. |
| `size` | integer | Size of the mapped region in bytes. |
| `entry` | hex | Entry point virtual address. |
| `checksum` | integer | PE header checksum. |
| `timedatestamp` | integer | PE compile timestamp (Unix seconds). |
| `is_wow64` | boolean | True if loaded in a WoW64 (32-bit) context. |

> **Note:** MemProcFS may add or rename columns between versions. Always verify against the actual header row in the output file.

---

## 5. Threads — `threads.csv`

**Extractor:** `ThreadsExtractor` | **Source:** `forensic_csv` (`threads.csv` + `modules.csv`) with **VFS ownership gate** (`pid/<PID>/threads/<TID>/info.txt`)

All kernel thread objects (ETHREAD) visible in memory, one row per thread. Case output keeps MemProcFS columns (PascalCase) and appends derived module fields plus `StartModuleStatus`.

MemProcFS source columns include: `PID`, `TID`, `ETHREAD`, `State`, `WaitReason`, `CreateTime`, `ExitTime`, `Running`, `BasePriority`, `Priority`, `ExitStatus`, `StartAddress`, `Win32StartAddress`, `IP`, `SP`, `TEB`, stack bounds, `TrapFrame`, `ImpersonationToken`.

| Field | Type | Description |
|-------|------|-------------|
| `PID` | integer | **Process ID** that owns this thread. |
| `TID` | integer | **Thread ID.** Unique identifier for this thread within the process. |
| `State` | string | **Thread state.** Kernel scheduler state: `Running`, `Ready`, `Waiting`, `Terminated`, etc. |
| `WaitReason` | string | **Wait reason.** If state is `Waiting`, the reason the thread is waiting (e.g. `Executive`, `UserRequest`, `DelayExecution`). |
| `Priority` | integer | **Current priority.** Dynamic thread priority (0–31). Higher = more scheduler time. |
| `BasePriority` | integer | **Base priority.** Priority set by the application, before any dynamic boost. |
| `StartAddress` | hex | **Thread start address** (`vaStartAddress`). Used when `Win32StartAddress` is zero/blank. |
| `Win32StartAddress` | hex | **Win32 start address** (`vaWin32StartAddress`). Preferred for module resolution when nonzero. |
| `ETHREAD` | hex | **ETHREAD kernel address.** Pointer to this thread's kernel object in memory. Not an EPROCESS address. |
| `TEB` | hex | **Thread Environment Block (TEB) address.** Per-thread user-mode data block. |
| `CreateTime` | datetime | **Thread creation timestamp.** When this thread was created (ETHREAD.CreateTime). |
| `ExitTime` | datetime | **Thread exit timestamp.** When this thread exited. Blank if still running. |
| `StartModuleName` | string | **Derived.** Containing EXE/DLL `Name` from `modules.csv` for the resolved start VA. |
| `StartModulePath` | string | **Derived.** Module `Path` (else `KernelPath`). |
| `StartModuleBase` | hex | **Derived.** Module image load address (`Start`) of the containing PE. |
| `StartModuleStatus` | string | **Derived.** Why module fields were filled or left empty (see below). |

**Ownership gate (default):** before module join, require MemProcFS VFS file `pid/<PID>/threads/<TID>/info.txt` and that its `ETHREAD:` value matches the CSV `ETHREAD` (normalized hex). Do **not** compare to `win-eprocess.txt` (that is EPROCESS, a different object). If the VFS tree is missing or ETHREAD mismatches, leave `StartModule*` empty.

**Module join (case output only):** same `PID` and `module.Start <= resolve_addr <= module.End` (inclusive; `End` reconstructed as `Start + Size - 1` when missing). Resolve address = nonzero `Win32StartAddress`, else `StartAddress`. On overlapping ranges, the tightest span wins.

**`--threads-allow-csv-only`:** skips the VFS gate (range join only). Use for lab trees that have only `forensic/csv/` and no `pid/` tree. Default remains VFS-required (fail closed).

| `StartModuleStatus` | Meaning |
|---------------------|---------|
| `ok` | Ownership passed (or csv-only) and VA hit a module range |
| `no_vfs_thread` | Missing `pid/<PID>/threads/<TID>/info.txt` (default mode) |
| `ethread_mismatch` | info.txt exists but ETHREAD ≠ CSV |
| `no_address` | Neither Win32 nor StartAddress usable |
| `no_modules_for_pid` | No `modules.csv` rows for this PID |
| `no_module` | Modules exist; resolved VA outside all ranges |

**Forensic use cases:**
- `StartModuleStatus=no_module` with a nonzero start VA = address outside known modules (shellcode / injection candidate), or torn-down / unlisted code.
- Prefer `Win32StartAddress` when triage-ing user-mode starts.
- Safest enrichment needs a MemProcFS mount (or saved tree) that still includes `pid/*/threads/*`, not CSV-only.

---

## 6. Windows Services — `services.csv`

**Extractor:** `ServicesExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/services.csv`)

Registry-backed Windows service entries extracted from the Service Control Manager database in memory.

| Field | Type | Description |
|-------|------|-------------|
| `ordinal` | integer | **Service ordinal.** Sequential index assigned by MemProcFS. |
| `pid` | integer | **Host process PID.** PID of the `svchost.exe` or standalone process hosting this service. 0 if not running. |
| `state` | string | **Service state.** `Running`, `Stopped`, `Paused`, `StartPending`, `StopPending`, etc. |
| `start_type` | string | **Startup type.** `Auto`, `Manual`, `Disabled`, `Boot`, `System`. |
| `binary_path` | string | **Image path.** Full command line used to start the service (e.g. `C:\Windows\system32\svchost.exe -k netsvcs`). May include arguments. |
| `service_name` | string | **Internal service name.** The short registry key name (e.g. `wuauserv`, `Schedule`). |
| `display_name` | string | **Display name.** Human-readable label shown in `services.msc` (e.g. `Windows Update`). |
| `run_as` | string | **Service account.** The account the service runs as (e.g. `LocalSystem`, `NT AUTHORITY\NetworkService`, a domain account). |

**Forensic use cases:**
- Services with `run_as=LocalSystem` and unusual `binary_path` locations (not `System32`) are high-priority suspects.
- Stopped services (`state=Stopped`) with a binary path that no longer exists = persistence artefact.

---

## 7. FindEvil Scan Results — `findevil.csv`

**Extractor:** `FindEvilExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/findevil.csv`)

Results of MemProcFS's built-in heuristic scanner that flags suspicious memory characteristics. One row per finding.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | **Process ID** where the anomaly was detected. |
| `name` | string | **Process image name** of the flagged process. |
| `type` | string | **Finding type / category.** E.g. `PROC_PROC`, `PE_INJECT`, `VAD_RX`, `NOLINK`, `BADHEADER`. Each type corresponds to a specific detection heuristic. |
| `description` | string | **Human-readable description** of what was found (e.g. `"32-bit PE found in non-PE memory region"`). |
| `detail` | string | **Technical detail.** Addresses, size, or other structured data supporting the finding. |
| `address` | hex | **Virtual address** of the suspicious memory region or object. |
| `note` | string | **Additional analyst note** from MemProcFS (may be empty). |

**Common `type` values:**

| Type | Meaning |
|------|---------|
| `PROC_PROC` | Process with no parent or broken process chain |
| `PE_INJECT` | PE image found injected in a non-module region |
| `VAD_RX` | Executable+writable VAD region (shellcode staging area) |
| `NOLINK` | Module not linked into the PEB loader list (hidden DLL) |
| `BADHEADER` | PE header is missing or malformed in memory |
| `PRIVATE_RX` | Private (non-file-backed) executable memory |

**Forensic use cases:**
- Every row in this file is pre-flagged as suspicious — triage highest-confidence `type` values first.
- Cross-reference `address` with `dlls.csv` `base_address` and `threads.csv` `start_address`.

---

## 8. Kernel Drivers — `drivers.csv`

**Extractor:** `DriversExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/drivers.csv`)

Loaded Windows kernel drivers enumerated from the kernel driver list.

| Field | Type | Description |
|-------|------|-------------|
| `offset` | hex | **Kernel object offset.** Address of the `_DRIVER_OBJECT` structure in kernel memory. |
| `base` | hex | **Module load base.** Virtual address where the driver image is loaded in kernel space. |
| `size` | integer | **Image size (bytes).** Size of the driver's kernel memory mapping. |
| `path` | string | **On-disk image path.** Full path to the `.sys` file (e.g. `\SystemRoot\system32\drivers\tcpip.sys`). |
| `name` | string | **Driver object name.** The name registered in the kernel (e.g. `\Driver\Tcpip`). |
| `service_name` | string | **SCM service name.** Corresponding Windows service registry key under `HKLM\SYSTEM\CurrentControlSet\Services`. |

**Forensic use cases:**
- Drivers with empty `path` or `path` pointing outside `System32\drivers` = high suspicion (rootkit).
- `base` not in the normal kernel range = manually mapped / hidden driver.

---

## 9. Open Handles — `handles.csv`

**Extractor:** `HandlesExtractor` | **Source:** `forensic_csv` (`handles.csv`) with **VFS ownership gate** (`pid/<PID>/handles/handles.txt`)

All open kernel object handles across all processes. One row per handle.

**MemProcFS source headers (typical):** `PID, Handle, Object, Access, Type, Tag, HandleCount, Device, Description`.

| Field | Type | Description |
|-------|------|-------------|
| `PID` | integer | **Process ID** that holds this handle. |
| `Handle` | hex | **Handle value.** The numeric handle as it appears in the process's handle table (multiple of 4). |
| `Object` | hex | **Kernel object address** for the handle. |
| `Access` | hex | **Granted access mask.** Bit-field of access rights granted when the handle was opened (e.g. `0x1f01ff` = full access on a file). |
| `Type` | string | **Object type.** Kernel object type string: `File`, `Process`, `Thread`, `Event`, `Mutant`, `Section`, `Key`, `Token`, `Port`, `Timer`, `Desktop`, `WindowStation`, etc. |
| `Tag` | string | Pool tag / type tag when present. |
| `HandleCount` | hex/int | Handle count for the object when present. |
| `Device` | string | Device association when present. |
| `Description` | string | **Object name / description.** For `File` handles: the file path. For `Key` handles: the registry key path. For `Process` handles: the target PID and name. May be empty for unnamed objects. |
| `ProcessName` | string | **Derived.** Owning process image name after ownership gate. |
| `ProcessNameStatus` | string | **Derived.** Why `ProcessName` is filled or empty (see below). |

**Ownership gate (default):** before filling `ProcessName`, require MemProcFS VFS file `pid/<PID>/handles/handles.txt` and that the CSV `(Handle, Object)` pair appears there (normalized hex). If the VFS tree is missing, the handle is absent, or the Object differs for that Handle, leave `ProcessName` empty.

After the gate passes, name resolution order is: `pid/<PID>/name.txt`, then forensic `process.csv` for that PID.

**`--handles-allow-csv-only`:** skips the VFS gate and joins by PID only (`name.txt` if present, else `process.csv`). Use for lab trees that have only `forensic/csv/` and no `pid/` tree. Default remains VFS-required (fail closed).

| `ProcessNameStatus` | Meaning |
|---------------------|---------|
| `ok` | Name filled after gate (or csv-only join) |
| `no_vfs_handle` | Missing `handles.txt` / PID path, or Handle not listed (default mode) |
| `object_mismatch` | Same Handle under PID, but Object address differs |
| `no_process` | Gate passed (or csv-only) but no name in `name.txt` / `process.csv` |

**Forensic use cases:**
- Process handles (`type=Process`) with `access` containing `PROCESS_VM_READ | PROCESS_VM_WRITE` = credential dumping candidate (LSASS targeting).
- `Section` handles to unusual paths = shared memory injection or process hollowing.
- `Mutant` handles with recognisable malware mutex names = malware family identification.
- Safest enrichment needs a MemProcFS mount (or saved tree) that still includes `pid/*/handles/*`, not CSV-only.

---

## 10. Scheduled Tasks — `tasks.csv`

**Extractor:** `TasksExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/tasks.csv`)

Windows Scheduled Tasks extracted from memory (Task Scheduler service structures).

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Task name.** Short identifier of the task (e.g. `\Microsoft\Windows\WindowsUpdate\sih`). |
| `path` | string | **Task path.** Full path in the Task Scheduler namespace. |
| `author` | string | **Author.** Who created the task (may be a domain or local username). |
| `description` | string | **Task description.** Human-readable description embedded in the task definition. |
| `command` | string | **Executable / action.** The program or script the task runs (e.g. `C:\Windows\system32\sc.exe`). |
| `arguments` | string | **Command-line arguments.** Arguments passed to `command` when the task fires. |
| `trigger` | string | **Trigger description.** What causes the task to run (e.g. `At logon`, `Daily at 03:00`, `On system start`). |

**Forensic use cases:**
- Tasks with `command` outside `System32` or pointing to `%TEMP%`, `AppData`, etc. = persistence mechanism.
- Tasks with `author` set to an unexpected user account.

---

## 11. Open Files — `files.csv`

**Extractor:** `FilesExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/files.csv`)

Open file objects enumerated from the kernel's file object table.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | **Process ID** holding the file object. |
| `process` | string | **Process image name.** |
| `address` | hex | **File object kernel address.** Pointer to the `_FILE_OBJECT` structure. |
| `type` | string | **Object type** (typically `File`). |
| `file` | string | **File path.** Full path including device notation (e.g. `\Device\HarddiskVolume3\Users\alice\Downloads\evil.exe`). |

---

## 12. Device Objects — `devices.csv`

**Extractor:** `DevicesExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/devices.csv`)

Kernel device objects, which represent hardware and virtual devices in the Windows device stack.

| Field | Type | Description |
|-------|------|-------------|
| `offset` | hex | **`_DEVICE_OBJECT` address.** Kernel address of this device object structure. |
| `major_function_table` | hex | **IRP major function table pointer.** Points to the dispatch table for this device — useful for detecting IRP hook rootkits. |
| `attached_device` | hex | **Attached device pointer.** Address of the next device in the device stack (filter drivers chain). `0` = no attachment. |
| `driver_path` | string | **Owning driver path.** On-disk path of the driver that created this device. |
| `volume_path` | string | **Volume path.** Mounted volume path if this is a storage device (e.g. `\Device\HarddiskVolume1`). |
| `device_name` | string | **Device name.** Named object path in `\Device\` namespace (e.g. `\Device\KeyboardClass0`). |
| `device_type` | string | **Device type code.** Numeric device type constant (e.g. `0x8` = `FILE_DEVICE_DISK`). |
| `flags` | string | **Device flags.** Bitmask from `_DEVICE_OBJECT.Flags` (e.g. `DO_BUFFERED_IO`, `DO_DIRECT_IO`). |

**Forensic use cases:**
- Devices whose `driver_path` does not match any entry in `drivers.csv` = hidden/rogue device.
- Modified `major_function_table` (IRP hooks) = kernel rootkit indicator.

---

## 13. Unloaded Modules — `unloaded_modules.csv`

**Extractor:** `UnloadedModulesExtractor` | **Source:** `forensic_csv` (MemProcFS `/forensic/csv/unloaded_modules.csv`)

Kernel-maintained ring buffer of recently unloaded drivers and modules. Windows keeps a limited history (typically ~50 entries) in `PsLoadedModuleList` before overwriting.

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | Owning process (0 = kernel module). |
| `name` | string | **Module short name** at the time it was unloaded. |
| `path` | string | **On-disk path** of the module that was unloaded. |
| `base` | hex | **Base address** where the module was loaded before being unloaded. |
| `size` | integer | **Size in bytes** of the unloaded module's mapping. |

**Forensic use cases:**
- Malware that loads a driver, does its work, and unloads it to evade detection — the artefact remains in this buffer.
- Cross-reference `base` + `size` with VAD entries that are now `MEM_FREE` to reconstruct the timeline.

---

## 14. Timelines — `timeline_*.csv`

**Extractor:** `TimelinesExtractor` | **Source:** `forensic_csv` (all files matching `timeline_` prefix)

MemProcFS generates a family of timeline CSVs, each correlating events from a different subsystem. All share the same base schema.

**Files produced:**

| File | Contents |
|------|----------|
| `timeline_all.csv` | Merged master timeline of all events |
| `timeline_process.csv` | Process create/exit events |
| `timeline_thread.csv` | Thread create/exit events |
| `timeline_ntfs.csv` | NTFS file system timestamps (MFT) |

**Pad column (all timeline CSVs):** MemProcFS header includes `Pad`, but `m_fc_csv.c` `M_FcCSV_ReadTimeline2` always writes it as fixed-width spaces (`"%*s"` with `""`) for line-length alignment — never forensic data. LeanMemFlow drops `Pad` from enriched case outputs where noted below.

**Process case-output headers:** `Time, Type, Action, PID, PPID, EprocessVirtualAddress, ProcessName, Account, KernelPath, ProcessDescription`. `ProcessDescription` is last (raw MemProcFS `Text`). Dropped: `Pad`.

**Thread case-output headers:** `Time, Type, Action, PID, TID, EThreadAddress, ThreadInfo`. Dropped: `Pad`.

**NTFS case-output headers:** After extraction enrichment, the case copy of `timeline_ntfs.csv` replaces generic MemProcFS column names with semantic names. The MemProcFS source file keeps the original headers.

| Case column | MemProcFS source | Description |
|-------------|------------------|-------------|
| `FileSize` | `Value32` | File size (raw string; not converted to decimal) |
| `MftRecordPhysicalAddress` | `Value64` | MFT record physical address (raw string; hex preserved) |
| `NtfsPath` | `Text` | NTFS file path (raw, unmodified) |

| `timeline_prefetch.csv` | Prefetch execution evidence |
| `timeline_net.csv` | Network connection events |

**Net case-output headers:** `ConnectionTime, Type, Action, PID, KernelObjectAddress, Protocol, State, SourceAddress, SourcePort, DestinationAddress, DestinationPort, ConnectionDescription`. `ConnectionDescription` is raw MemProcFS `Text`. Dropped: `Value32`, `Pad`.

| `timeline_task.csv` | Scheduled task execution events |

**Task case-output headers:** `Time, Type, Action, TaskName, CommandLine, Parameters, User, TaskDescription`. `TaskDescription` is last (raw MemProcFS `Text`). Dropped: `PID`, `Value32`, `Value64`, `Pad`.

| `timeline_registry.csv` | Registry timeline events |

**Registry case-output headers:** `Time, Type, Action, RegistryPath`. Dropped: `PID`, `Value32`, `Value64`, `Text`, `Pad`.

| `timeline_kernelobject.csv` | Kernel object manager objects |

**Kernel object case-output headers:** After extraction enrichment, the case copy of `timeline_kernelobject.csv` uses semantic names. MemProcFS source keeps the original headers. Verified against MemProcFS wiki (KObj: NUM unused, HEX = object address) and `m_sys_obj.c` `MSysObj_Timeline` (`dwPID=0`, `dwData32=0`, `qwData64=va`, `uszText=path`).

| Case column | MemProcFS source | Description |
|-------------|------------------|-------------|
| `ObjectAddress` | `Value64` | Kernel object virtual address |
| `KernelObjectPath` | `Text` | Full object manager path |

Dropped (always unset for KObj): `PID`, `Value32`, `Pad`.

| `timeline_web.csv` | Browser history artefacts |

**Web case-output headers:** After extraction enrichment, the case copy of `timeline_web.csv` uses semantic names. MemProcFS source keeps the original headers. Verified against `m_fc_web.c` `MWeb_FcTimeline` (`dwPID=browser PID`, `dwData32=0`, `qwData64=0`, `uszText=browser:[…] type:[…] url:[…] info:[…]`).

| Case column | MemProcFS source | Description |
|-------------|------------------|-------------|
| `PID` | `PID` | Browser process ID (kept; populated by MemProcFS) |
| `Browser` | parsed from `Text` | Browser name (e.g. `chrome`, `msedge`, `firefox`) |
| `WebAction` | parsed from `Text` | Web event type (e.g. `visit`, `download`, `loginpwd`) |
| `Url` | parsed from `Text` | URL |
| `Info` | parsed from `Text` | Extra info (title, filename, username, etc.) |
| `WebDescription` | `Text` | Raw MemProcFS description string |

Dropped (always unset for WEB): `Value32`, `Value64`, `Pad`.

**Common fields across all timeline files:**

| Field | Type | Description |
|-------|------|-------------|
| `time` | datetime | **Event timestamp.** UTC timestamp of the event (ISO 8601 format, e.g. `2024-01-15 08:32:11`). |
| `type` | string | **Subsystem type.** Short code identifying the data source: `PROC` (process), `NET` (network), `NTFS` (filesystem), `REG` (registry), `PREFETCH`, `TASK`, `THREAD`, `WEB`. |
| `action` | string | **Event action.** What happened: `Create`, `Terminate`, `Connect`, `Read`, `Write`, `Delete`, `Execute`, etc. |
| `pid` | integer | **Related Process ID.** The PID associated with this event. `0` for kernel events. |
| `path` | string | **Related path.** File path, registry key, URL, or object name relevant to this event. |
| `description` | string | **Event description.** Free-text detail about the event (process name + args, file operation details, etc.). |

**Forensic use cases:**
- `timeline_all.csv` is the primary pivot for building an attack timeline.
- Sort by `time`, filter `type=NET` + `PROC`, and look for beaconing patterns.
- `timeline_ntfs.csv` reveals file drops that precede process creation events. Use `FileSize`, `MftRecordPhysicalAddress`, and `NtfsPath` in the enriched case copy.

---

## Summary Table

| Extractor | Output File | Source | Key Fields |
|-----------|-------------|--------|------------|
| processes | `process.csv` | forensic_csv | pid, ppid, name, path, user, cmdline, create_time, wow64 |
| netstat | `net.csv` | forensic_csv (net.csv) / vfs fallback | pid, protocol, state, src-addr, src-port, dst-addr, dst-port |
| dlls | `dlls.csv` | forensic_csv (modules.csv) + optional dump PE | pid, module_name, module_type, base_address, entry_point, entry_point_rva, pe_timedatestamp, pe_checksum |
| modules | `modules.csv` | forensic_csv | pid, name, path, base, size, entry |
| threads | `threads.csv` | forensic_csv + VFS pid/threads gate (+ modules) | PID, TID, ETHREAD, StartModuleName, StartModuleBase, StartModuleStatus |
| services | `services.csv` | forensic_csv | pid, state, start_type, binary_path, service_name, run_as |
| findevil | `findevil.csv` | forensic_csv | pid, name, type, description, address |
| drivers | `drivers.csv` | forensic_csv | offset, base, size, path, name, service_name |
| handles | `handles.csv` | forensic_csv + VFS pid/handles gate | PID, Handle, Object, ProcessName, ProcessNameStatus |
| tasks | `tasks.csv` | forensic_csv | name, path, command, arguments, trigger |
| files | `files.csv` | forensic_csv | pid, address, file |
| devices | `devices.csv` | forensic_csv | offset, driver_path, device_name, major_function_table |
| unloaded_modules | `unloaded_modules.csv` | forensic_csv | pid, name, path, base, size |
| timelines | `timeline_*.csv` | forensic_csv | time, type, action, pid, path, description |

---

## Source Types Explained

| Source | Mechanism | Reliability |
|--------|-----------|-------------|
| `api` | MemProcFS Python API — parses kernel structures directly from the memory dump. Fields are computed by MemProcFS. | High — direct kernel parsing |
| `vfs` | Reads a text file exposed in MemProcFS's virtual filesystem (e.g. `/sys/net/netstat.txt`). Parsed by the extractor. | High — same kernel data via different interface |
| `forensic_csv` | Copies a pre-built CSV that MemProcFS generates during its forensic scan phase (requires `vmm.vfs.list("/forensic/csv/")` to be populated). | High, but depends on MemProcFS forensic mode being enabled |

> **forensic_csv note:** MemProcFS must be run with forensic mode enabled (e.g. `--forensic 1`) for `/forensic/csv/` files to exist. If a forensic CSV is missing, the extractor returns `ok=False` and logs a warning — it does **not** crash.

---

*Document version: 1.0 — 2026-03-10*
