"""One-time direct UEFI launch for the dedicated hyper-reV directory.

Inspect/plan are read-only. Arm writes only a fresh Boot#### and BootNext.
BootOrder, Microsoft boot files, and restart scheduling are outside this tool.
Plans retain the exact original firmware values for guarded rollback.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import uuid

NAMESPACE = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
LOADER = r"\EFI\hyper-reV\uefi-boot-standalone.efi"
DESCRIPTION = "hyper-reV standalone EFI (one-time)"
END_NODE = b"\x7f\xff\x04\x00"


@dataclass(frozen=True)
class Variable:
    attributes: int
    data: bytes

    def record(self):
        return {"attributes": self.attributes, "base64": base64.b64encode(self.data).decode("ascii")}

    @classmethod
    def from_record(cls, value):
        return None if value is None else cls(int(value["attributes"]), base64.b64decode(value["base64"], validate=True))


def record(value):
    return None if value is None else value.record()


class NativeFirmware:
    """Documented Win32 variable APIs; privilege changes stay in this process."""
    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("Native firmware access requires Windows")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.a = ctypes.WinDLL("advapi32", use_last_error=True)

        class Luid(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class Privileges(ctypes.Structure):
            _fields_ = [("Count", wintypes.DWORD), ("Luid", Luid), ("Attributes", wintypes.DWORD)]

        self.P = Privileges
        self.k.GetCurrentProcess.restype = wintypes.HANDLE
        self.k.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k.CloseHandle.restype = wintypes.BOOL
        self.a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        self.a.OpenProcessToken.restype = wintypes.BOOL
        self.a.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(Luid)]
        self.a.LookupPrivilegeValueW.restype = wintypes.BOOL
        self.a.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(Privileges), wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
        self.a.AdjustTokenPrivileges.restype = wintypes.BOOL
        self.k.GetFirmwareEnvironmentVariableExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.k.GetFirmwareEnvironmentVariableExW.restype = wintypes.DWORD
        self.k.SetFirmwareEnvironmentVariableExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        self.k.SetFirmwareEnvironmentVariableExW.restype = wintypes.BOOL
        self.token = wintypes.HANDLE()
        self.previous = Privileges()
        if not self.a.OpenProcessToken(self.k.GetCurrentProcess(), 0x28, ctypes.byref(self.token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            desired = Privileges()
            desired.Count, desired.Attributes = 1, 2
            if not self.a.LookupPrivilegeValueW(None, "SeSystemEnvironmentPrivilege", ctypes.byref(desired.Luid)):
                raise ctypes.WinError(ctypes.get_last_error())
            size = wintypes.DWORD()
            ctypes.set_last_error(0)
            ok = self.a.AdjustTokenPrivileges(self.token, False, ctypes.byref(desired), ctypes.sizeof(self.previous), ctypes.byref(self.previous), ctypes.byref(size))
            error = ctypes.get_last_error()
            if not ok or error:
                raise ctypes.WinError(error)
        except BaseException:
            self.k.CloseHandle(self.token)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            if self.previous.Count:
                if not self.a.AdjustTokenPrivileges(self.token, False, ctypes.byref(self.previous), 0, None, None):
                    raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.k.CloseHandle(self.token)

    def get(self, name):
        buffer = ctypes.create_string_buffer(1024 * 1024)
        attributes = wintypes.DWORD()
        size = self.k.GetFirmwareEnvironmentVariableExW(name, NAMESPACE, buffer, len(buffer), ctypes.byref(attributes))
        if size:
            return Variable(attributes.value, buffer.raw[:size])
        error = ctypes.get_last_error()
        if error == 203:  # ERROR_ENVVAR_NOT_FOUND only; access errors are fatal.
            return None
        raise ctypes.WinError(error)

    def volume_relative_path(self, path):
        self.k.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        self.k.GetVolumePathNameW.restype = wintypes.BOOL
        root = ctypes.create_unicode_buffer(32768)
        resolved = Path(path).resolve()
        if not self.k.GetVolumePathNameW(str(resolved), root, len(root)):
            raise ctypes.WinError(ctypes.get_last_error())
        relative = resolved.relative_to(Path(root.value))
        return "\\" + "\\".join(relative.parts)

    def partition_guid(self, path):
        """Read the actual GPT partition ID for a file, independent of mount letters."""
        self.k.GetVolumePathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        self.k.GetVolumePathNameW.restype = wintypes.BOOL
        self.k.GetVolumeNameForVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        self.k.GetVolumeNameForVolumeMountPointW.restype = wintypes.BOOL
        self.k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.k.CreateFileW.restype = wintypes.HANDLE
        self.k.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        self.k.DeviceIoControl.restype = wintypes.BOOL
        root, volume = ctypes.create_unicode_buffer(32768), ctypes.create_unicode_buffer(32768)
        if not self.k.GetVolumePathNameW(str(path), root, len(root)) or not self.k.GetVolumeNameForVolumeMountPointW(root.value, volume, len(volume)):
            raise ctypes.WinError(ctypes.get_last_error())
        handle = self.k.CreateFileW(volume.value.rstrip("\\"), 0, 7, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            buffer, returned = ctypes.create_string_buffer(256), wintypes.DWORD()
            if not self.k.DeviceIoControl(handle, 0x70048, None, 0, buffer, len(buffer), ctypes.byref(returned), None):
                raise ctypes.WinError(ctypes.get_last_error())
            # Win64 PARTITION_INFORMATION_EX: union at 32, GPT PartitionId at 48.
            if returned.value < 144 or struct.unpack_from("<I", buffer.raw)[0] != 1:
                raise ValueError("Selected file is outside a GPT partition")
            if uuid.UUID(bytes_le=buffer.raw[32:48]) != uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"):
                raise ValueError("Selected file resides outside an EFI system partition")
            return str(uuid.UUID(bytes_le=buffer.raw[48:64]))
        finally:
            self.k.CloseHandle(handle)

    def put(self, name, value):
        if name == "BootOrder" or (name != "BootNext" and (len(name) != 8 or not name.startswith("Boot") or any(c not in "0123456789ABCDEF" for c in name[4:]))):
            raise ValueError("Writes are restricted to BootNext and individual Boot#### variables")
        data = b"" if value is None else value.data
        attributes = 0 if value is None else value.attributes
        buffer = ctypes.create_string_buffer(data) if data else None
        if not self.k.SetFirmwareEnvironmentVariableExW(name, NAMESPACE, buffer, len(data), attributes):
            raise ctypes.WinError(ctypes.get_last_error())


@contextmanager
def mutation_lock(fw):
    """Serialize this CLI; the UEFI API itself has no cross-writer CAS primitive."""
    k = fw.k
    k.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    k.CreateMutexW.restype = wintypes.HANDLE
    k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k.WaitForSingleObject.restype = wintypes.DWORD
    k.ReleaseMutex.argtypes = [wintypes.HANDLE]
    k.ReleaseMutex.restype = wintypes.BOOL
    handle = k.CreateMutexW(None, False, r"Global\hyper-reV-firmware-boot")
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    owned = False
    try:
        wait = k.WaitForSingleObject(handle, 0)
        owned = wait in (0, 0x80)
        if not owned:
            raise RuntimeError("Another firmware-boot operation holds the mutation lock")
        if wait == 0x80:
            raise RuntimeError("Previous operation was interrupted; inspect firmware and its saved plan first")
        yield
    finally:
        if owned:
            k.ReleaseMutex(handle)
        k.CloseHandle(handle)


def indices(value):
    if value is None or not value.data or len(value.data) % 2:
        raise ValueError("Missing or malformed UINT16 boot-option list")
    return list(struct.unpack("<" + "H" * (len(value.data) // 2), value.data))


def parse_option(data):
    if len(data) < 8:
        raise ValueError("Truncated EFI_LOAD_OPTION")
    attributes, path_size = struct.unpack_from("<IH", data)
    pos = 6
    while pos + 2 <= len(data) and data[pos:pos + 2] != b"\0\0":
        pos += 2
    if pos + 2 > len(data) or pos + 2 + path_size > len(data):
        raise ValueError("Truncated description or device path")
    description = data[6:pos].decode("utf-16le")
    start, end = pos + 2, pos + 2 + path_size
    nodes = []
    pos = start
    while pos < end:
        if end - pos < 4:
            raise ValueError("Truncated device-path header")
        kind, subtype, length = struct.unpack_from("<BBH", data, pos)
        if length < 4 or pos + length > end:
            raise ValueError("Invalid device-path node length")
        nodes.append((kind, subtype, data[pos:pos + length]))
        pos += length
    if not nodes or nodes[-1][2] != END_NODE:
        raise ValueError("Missing end-of-entire-path node")
    return {"attributes": attributes, "description": description, "nodes": nodes, "optional": data[end:]}


def make_option(reference, esp_guid):
    option = parse_option(reference.data)
    nodes = option["nodes"]
    files = [i for i, (kind, subtype, _) in enumerate(nodes) if (kind, subtype) == (4, 4)]
    drives = [raw for kind, subtype, raw in nodes if (kind, subtype) == (4, 1)]
    if len(files) != 1 or files[0] != len(nodes) - 2 or len(drives) != 1:
        raise ValueError("Reference requires one hard-drive node followed by one final file path")
    if any(kind == 0x7F for kind, _, _ in nodes[:-1]):
        raise ValueError("Multiple device-path instances require separate review")
    drive = drives[0]
    if len(drive) != 42 or drive[40:] != b"\x02\x02" or uuid.UUID(bytes_le=drive[24:40]) != uuid.UUID(esp_guid):
        raise ValueError("Reference GPT partition differs from the selected ESP")
    original = nodes[files[0]][2][4:].decode("utf-16le").rstrip("\0")
    if original.lower() != r"\efi\microsoft\boot\bootmgfw.efi":
        raise ValueError("Reference is not the original Windows boot manager")
    path_text = (LOADER + "\0").encode("utf-16le")
    file_node = struct.pack("<BBH", 4, 4, 4 + len(path_text)) + path_text
    path = b"".join(raw for _, _, raw in nodes[:files[0]]) + file_node + END_NODE
    # Deliberately omit Microsoft's WINDOWS/BCDOBJECT optional data.
    return Variable(7, struct.pack("<IH", 1, len(path)) + (DESCRIPTION + "\0").encode("utf-16le") + path)


def file_identity(path):
    data = path.read_bytes()
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError(f"Invalid PE file: {path}")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe + 24 + 112 > len(data) or data[pe:pe + 4] != b"PE\0\0" or struct.unpack_from("<H", data, pe + 4)[0] != 0x8664:
        raise ValueError(f"Invalid x64 PE headers: {path}")
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise ValueError(f"Expected PE32+: {path}")
    if path.suffix.lower() == ".efi" and struct.unpack_from("<H", data, opt + 68)[0] != 10:
        raise ValueError(f"Expected EFI_APPLICATION: {path}")
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def make_plan(fw, directory, esp_guid, reference_name="Boot0000"):
    order, previous_next = fw.get("BootOrder"), fw.get("BootNext")
    used = set(indices(order))
    if previous_next is not None:
        raise ValueError("Existing BootNext is reserved for another request")
    reference = fw.get(reference_name)
    if reference is None or int(reference_name[4:], 16) not in used:
        raise ValueError("Reference boot option is missing from the normal order")
    created = make_option(reference, esp_guid)
    number = next((i for i in range(65536) if i not in used and fw.get(f"Boot{i:04X}") is None), None)
    if number is None:
        raise ValueError("Firmware boot-option namespace is full")
    directory = directory.resolve()
    if uuid.UUID(fw.partition_guid(directory)) != uuid.UUID(esp_guid):
        raise ValueError("Staged directory resides on a different GPT partition")
    if fw.volume_relative_path(directory).lower() != r"\efi\hyper-rev":
        raise ValueError("Directory differs from the firmware option's volume-relative path")
    files = [file_identity(directory / name) for name in ("uefi-boot-standalone.efi", "hyperv-attachment.dll")]
    # The loader chains this original file on the same ESP. Include its identity.
    files.append(file_identity(directory.parent / "Microsoft" / "Boot" / "bootmgfw.efi"))
    return {"schema": 1, "boot_name": f"Boot{number:04X}", "boot_number": number, "loader": LOADER,
            "esp_guid": str(uuid.UUID(esp_guid)), "description": DESCRIPTION,
            "boot_order_before": record(order), "boot_next_before": record(previous_next),
            "reference_name": reference_name, "reference_before": record(reference),
            "directory": str(directory),
            "created_option": record(created), "files": files, "restart_scheduled": False}


def check_plan(plan):
    number = plan["boot_number"]
    if plan["schema"] != 1 or type(number) is not int or not 0 <= number <= 65535 or plan["boot_name"] != f"Boot{number:04X}" or plan["loader"] != LOADER:
        raise ValueError("Invalid firmware plan")
    if number in indices(Variable.from_record(plan["boot_order_before"])):
        raise ValueError("Planned number belongs to the preserved boot order")
    reference = Variable.from_record(plan["reference_before"])
    if Variable.from_record(plan["created_option"]) != make_option(reference, plan["esp_guid"]):
        raise ValueError("Planned option differs from the reference-derived EFI path")
    if plan["boot_next_before"] is not None:
        raise ValueError("This tool preserves existing BootNext requests")
    directory = Path(plan["directory"])
    expected = [directory / "uefi-boot-standalone.efi", directory / "hyperv-attachment.dll", directory.parent / "Microsoft" / "Boot" / "bootmgfw.efi"]
    files = plan["files"]
    if not directory.is_absolute() or directory.name.lower() != "hyper-rev" or directory.parent.name.lower() != "efi" or len(files) != len(expected):
        raise ValueError("The plan requires the dedicated EFI/hyper-reV directory and all three file identities")
    for identity, path in zip(files, expected):
        digest = identity.get("sha256", "")
        if Path(identity["path"]) != path or type(identity.get("bytes")) is not int or identity["bytes"] <= 0 or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid planned file path or identity")


def arm(fw, plan):
    check_plan(plan)
    for name, key in (("BootOrder", "boot_order_before"), ("BootNext", "boot_next_before"), (plan["reference_name"], "reference_before")):
        if fw.get(name) != Variable.from_record(plan[key]):
            raise ValueError(f"Firmware state changed since planning: {name}")
    name = plan["boot_name"]
    if fw.get(name) is not None:
        raise ValueError(f"Another option now owns {name}")
    if fw.volume_relative_path(Path(plan["directory"])).lower() != r"\efi\hyper-rev":
        raise ValueError("Planned directory differs from the firmware option's volume-relative path")
    for identity in plan["files"]:
        path = Path(identity["path"])
        if uuid.UUID(fw.partition_guid(path)) != uuid.UUID(plan["esp_guid"]):
            raise ValueError(f"Planned file resides on another partition: {path}")
        if file_identity(path) != identity:
            raise ValueError(f"Staged file changed since planning: {identity['path']}")
    created = Variable.from_record(plan["created_option"])
    wanted_next = Variable(7, struct.pack("<H", plan["boot_number"]))
    # Recheck ownership after hashing; native UEFI APIs offer no atomic CAS.
    if fw.get(name) is not None or fw.get("BootOrder") != Variable.from_record(plan["boot_order_before"]):
        raise ValueError("Firmware option allocation changed before writing")
    if fw.get("BootNext") is not None:
        raise ValueError("Another BootNext request appeared before writing")
    # A durably saved CLI plan is the recovery journal for partial API failures.
    fw.put(name, created)
    if fw.get(name) != created:
        raise RuntimeError(f"Firmware readback differs: {name}; use rollback")
    if fw.get("BootNext") is not None or fw.get("BootOrder") != Variable.from_record(plan["boot_order_before"]):
        raise RuntimeError("Firmware state changed before arming; use rollback")
    fw.put("BootNext", wanted_next)
    if fw.get("BootNext") != wanted_next or fw.get("BootOrder") != Variable.from_record(plan["boot_order_before"]):
        raise RuntimeError("Firmware readback differs after arming; use rollback")
    return {"armed": True, "boot_name": name, "boot_next": plan["boot_number"], "boot_order_unchanged": True, "restart_scheduled": False}


def rollback(fw, plan):
    check_plan(plan)
    name = plan["boot_name"]
    created = Variable.from_record(plan["created_option"])
    current = fw.get(name)
    if current is not None and current != created:
        raise ValueError(f"Rollback stopped: {name} belongs to a different option")
    current_next = fw.get("BootNext")
    wanted_next = Variable(7, struct.pack("<H", plan["boot_number"]))
    if current_next is not None and current_next != wanted_next:
        raise ValueError("Rollback preserves another pending BootNext request")
    if plan["boot_number"] in indices(fw.get("BootOrder")):
        raise ValueError("Firmware added this option to BootOrder; preserve it for manual review")
    # Preflight every guard before the first mutation, then recheck ownership.
    if fw.get(name) != current or fw.get("BootNext") != current_next:
        raise ValueError("Firmware ownership changed during rollback checks")
    if current_next is not None:
        fw.put("BootNext", None)
        if fw.get("BootNext") is not None:
            raise RuntimeError("BootNext deletion failed readback")
    if current is not None:
        if fw.get(name) != created or fw.get("BootNext") is not None or plan["boot_number"] in indices(fw.get("BootOrder")):
            raise ValueError("Firmware ownership changed before option deletion")
        fw.put(name, None)
        if fw.get(name) is not None:
            raise RuntimeError("Boot option deletion failed readback")
    return {"rolled_back": True, "boot_name": name, "restart_scheduled": False}


def inspect(fw):
    result = {name: record(fw.get(name)) for name in ("BootOrder", "BootNext", "BootCurrent")}
    names = [f"Boot{i:04X}" for i in indices(Variable.from_record(result["BootOrder"]))]
    next_var = Variable.from_record(result["BootNext"])
    if next_var is not None:
        if len(next_var.data) != 2:
            raise ValueError("Malformed BootNext")
        names.append(f"Boot{struct.unpack('<H', next_var.data)[0]:04X}")
    result["options"] = {}
    for name in dict.fromkeys(names):
        value = fw.get(name)
        item = record(value)
        if value is not None:
            option = parse_option(value.data)
            item.update(description=option["description"], load_attributes=option["attributes"], device_path_hex=b"".join(n[2] for n in option["nodes"]).hex(), optional_data_bytes=len(option["optional"]))
        result["options"][name] = item
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("inspect")
    plan_parser = commands.add_parser("plan")
    plan_parser.add_argument("--directory", type=Path, required=True)
    plan_parser.add_argument("--esp-guid", required=True)
    plan_parser.add_argument("--output", type=Path, required=True)
    plan_parser.add_argument("--reference", default="Boot0000", help="Verified original Windows firmware option")
    for command in ("arm", "rollback"):
        commands.add_parser(command).add_argument("plan", type=Path)
    args = parser.parse_args()
    with NativeFirmware() as fw:
        if args.command == "inspect":
            result = inspect(fw)
        elif args.command == "plan":
            result = make_plan(fw, args.directory, args.esp_guid, args.reference)
            check_plan(result)
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        else:
            plan = json.loads(args.plan.read_text(encoding="utf-8-sig"))
            with mutation_lock(fw):
                result = arm(fw, plan) if args.command == "arm" else rollback(fw, plan)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
