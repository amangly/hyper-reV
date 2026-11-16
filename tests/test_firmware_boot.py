"""Pure unit tests; these never instantiate the Windows firmware API."""
import copy
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import firmware_boot as boot

GUID = "11111111-2222-4333-8444-555555555555"


def reference():
    drive = struct.pack("<BBHIQQ16sBB", 4, 1, 42, 1, 2048, 409600, uuid.UUID(GUID).bytes_le, 2, 2)
    text = (r"\EFI\Microsoft\Boot\bootmgfw.efi" + "\0").encode("utf-16le")
    path = drive + struct.pack("<BBH", 4, 4, len(text) + 4) + text + boot.END_NODE
    return boot.Variable(7, struct.pack("<IH", 1, len(path)) + "Windows Boot Manager\0".encode("utf-16le") + path + b"WINDOWS\0BCDOBJECT=old")


class MemoryFirmware:
    def __init__(self, volume_root):
        self.volume_root = volume_root
        self.values = {"BootOrder": boot.Variable(7, struct.pack("<HH", 0, 8)), "Boot0000": reference(), "Boot0008": reference()}
        self.writes = []
        self.fail_name = None

    def get(self, name):
        return self.values.get(name)

    def partition_guid(self, path):
        return GUID

    def volume_relative_path(self, path):
        return "\\" + "\\".join(Path(path).relative_to(self.volume_root).parts)

    def put(self, name, value):
        if name == "BootOrder":
            raise AssertionError("BootOrder is outside the write scope")
        self.writes.append((name, value))
        if name == self.fail_name:
            raise OSError("Injected firmware write failure")
        if value is None:
            self.values.pop(name, None)
        else:
            self.values[name] = value


class FirmwareBootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "EFI" / "hyper-reV"
        self.directory.mkdir(parents=True)
        windows = self.directory.parent / "Microsoft" / "Boot"
        windows.mkdir(parents=True)
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<H", data, 132, 0x8664)
        struct.pack_into("<H", data, 152, 0x20B)
        struct.pack_into("<H", data, 220, 10)
        for path in (self.directory / "uefi-boot-standalone.efi", self.directory / "hyperv-attachment.dll", windows / "bootmgfw.efi"):
            path.write_bytes(data)
        self.fw = MemoryFirmware(Path(self.tmp.name))
        self.plan = boot.make_plan(self.fw, self.directory, GUID)

    def test_plan_is_read_only_and_preserves_optional_data_boundary(self):
        self.assertEqual(self.fw.writes, [])
        option = boot.parse_option(boot.Variable.from_record(self.plan["created_option"]).data)
        self.assertEqual(option["description"], boot.DESCRIPTION)
        self.assertEqual(option["attributes"], 1)
        self.assertEqual(option["optional"], b"")
        self.assertEqual(option["nodes"][0][2], boot.parse_option(reference().data)["nodes"][0][2])
        self.assertEqual(option["nodes"][-2][2][4:].decode("utf-16le"), boot.LOADER + "\0")

    def test_arm_uses_firmware_next_and_leaves_order_identical(self):
        before = self.fw.get("BootOrder")
        result = boot.arm(self.fw, self.plan)
        self.assertTrue(result["armed"])
        self.assertEqual([name for name, _ in self.fw.writes], [self.plan["boot_name"], "BootNext"])
        self.assertEqual(self.fw.get("BootNext"), boot.Variable(7, struct.pack("<H", self.plan["boot_number"])))
        self.assertEqual(self.fw.get("BootOrder"), before)

    def test_rollback_is_idempotent_before_and_after_consumption(self):
        boot.arm(self.fw, self.plan)
        boot.rollback(self.fw, self.plan)
        boot.rollback(self.fw, self.plan)
        self.assertIsNone(self.fw.get(self.plan["boot_name"]))
        self.assertIsNone(self.fw.get("BootNext"))
        self.fw.writes.clear()
        boot.arm(self.fw, self.plan)
        self.fw.values.pop("BootNext")  # Firmware consumes it before executing the image.
        boot.rollback(self.fw, self.plan)
        self.assertEqual(self.fw.get("BootOrder"), boot.Variable.from_record(self.plan["boot_order_before"]))

    def test_preexisting_next_is_preserved(self):
        self.fw.values["BootNext"] = boot.Variable(7, b"\x08\x00")
        with self.assertRaises(ValueError):
            boot.make_plan(self.fw, self.directory, GUID)
        self.assertEqual(self.fw.writes, [])

    def test_changed_order_or_reference_prevents_all_writes(self):
        for name in ("BootOrder", "Boot0000"):
            original = self.fw.values[name]
            self.fw.values[name] = boot.Variable(7, original.data + b"\0\0")
            with self.assertRaises(ValueError):
                boot.arm(self.fw, self.plan)
            self.fw.values[name] = original
        self.assertEqual(self.fw.writes, [])

    def test_changed_file_prevents_all_writes(self):
        (self.directory / "hyperv-attachment.dll").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            boot.arm(self.fw, self.plan)
        self.assertEqual(self.fw.writes, [])

    def test_occupied_number_is_preserved(self):
        self.fw.values[self.plan["boot_name"]] = reference()
        with self.assertRaises(ValueError):
            boot.arm(self.fw, self.plan)
        self.assertEqual(self.fw.writes, [])

    def test_api_read_errors_are_fatal(self):
        original = self.fw.get
        def fail(name):
            if name == "Boot0001":
                raise PermissionError("Access denied is distinct from missing")
            return original(name)
        self.fw.get = fail
        with self.assertRaises(PermissionError):
            boot.make_plan(self.fw, self.directory, GUID)
        self.assertEqual(self.fw.writes, [])

    def test_failed_next_write_can_be_rolled_back(self):
        self.fw.fail_name = "BootNext"
        with self.assertRaises(OSError):
            boot.arm(self.fw, self.plan)
        self.fw.fail_name = None
        boot.rollback(self.fw, self.plan)
        self.assertIsNone(self.fw.get(self.plan["boot_name"]))
        self.assertIsNone(self.fw.get("BootNext"))

    def test_rollback_preserves_other_pending_request(self):
        boot.arm(self.fw, self.plan)
        self.fw.values["BootNext"] = boot.Variable(7, b"\x08\x00")
        with self.assertRaises(ValueError):
            boot.rollback(self.fw, self.plan)
        self.assertIsNotNone(self.fw.get(self.plan["boot_name"]))
        self.assertEqual(self.fw.get("BootNext").data, b"\x08\x00")

    def test_rollback_preserves_replaced_option(self):
        boot.arm(self.fw, self.plan)
        self.fw.values[self.plan["boot_name"]] = reference()
        with self.assertRaises(ValueError):
            boot.rollback(self.fw, self.plan)
        self.assertIsNotNone(self.fw.get("BootNext"))

    def test_rollback_preserves_option_firmware_added_to_order(self):
        boot.arm(self.fw, self.plan)
        self.fw.values["BootOrder"] = boot.Variable(7, struct.pack("<HHH", 0, 8, self.plan["boot_number"]))
        previous_next = self.fw.get("BootNext")
        self.fw.writes.clear()
        with self.assertRaises(ValueError):
            boot.rollback(self.fw, self.plan)
        self.assertIsNotNone(self.fw.get(self.plan["boot_name"]))
        self.assertEqual(self.fw.get("BootNext"), previous_next)
        self.assertEqual(self.fw.writes, [])

    def test_missing_or_reordered_file_identities_are_rejected(self):
        for files in ([], self.plan["files"][:2], self.plan["files"][::-1]):
            altered = copy.deepcopy(self.plan)
            altered["files"] = files
            with self.assertRaises(ValueError):
                boot.arm(self.fw, altered)
        self.assertEqual(self.fw.writes, [])

    def test_partition_mismatch_prevents_all_writes(self):
        self.fw.partition_guid = lambda path: str(uuid.UUID(int=0))
        with self.assertRaises(ValueError):
            boot.arm(self.fw, self.plan)
        self.assertEqual(self.fw.writes, [])

    def test_nested_directory_on_same_partition_is_rejected(self):
        nested = Path(self.tmp.name) / "backup" / "EFI" / "hyper-reV"
        with self.assertRaises(ValueError):
            boot.make_plan(self.fw, nested, GUID)
        altered = copy.deepcopy(self.plan)
        altered["directory"] = str(nested)
        paths = [nested / "uefi-boot-standalone.efi", nested / "hyperv-attachment.dll", nested.parent / "Microsoft" / "Boot" / "bootmgfw.efi"]
        for identity, path in zip(altered["files"], paths):
            identity["path"] = str(path)
        with self.assertRaises(ValueError):
            boot.arm(self.fw, altered)
        self.assertEqual(self.fw.writes, [])

    def test_racing_slot_allocation_after_hashing_is_preserved(self):
        original = boot.file_identity
        def file_changed(path):
            result = original(path)
            self.fw.values[self.plan["boot_name"]] = reference()
            return result
        boot.file_identity = file_changed
        try:
            with self.assertRaises(ValueError):
                boot.arm(self.fw, self.plan)
        finally:
            boot.file_identity = original
        self.assertEqual(self.fw.writes, [])
        self.assertEqual(self.fw.get(self.plan["boot_name"]), reference())

    def test_invalid_guid_and_reference_are_rejected(self):
        with self.assertRaises(ValueError):
            boot.make_option(reference(), str(uuid.UUID(int=0)))
        broken = boot.Variable(7, reference().data.replace("bootmgfw".encode("utf-16le"), "othermgr".encode("utf-16le")))
        with self.assertRaises(ValueError):
            boot.make_option(broken, GUID)

    def test_truncated_or_zero_length_device_nodes_are_rejected(self):
        for data in (b"", reference().data[:10], struct.pack("<IH", 1, 4) + b"\0\0" + b"\x04\x01\0\0"):
            with self.assertRaises(ValueError):
                boot.parse_option(data)

    def test_manipulated_plan_option_and_index_are_rejected(self):
        for key, value in (("boot_name", "Boot0000"), ("boot_number", 0), ("loader", r"\EFI\other.efi"), ("created_option", reference().record())):
            altered = copy.deepcopy(self.plan)
            altered[key] = value
            with self.assertRaises(ValueError):
                boot.arm(self.fw, altered)
        self.assertEqual(self.fw.writes, [])


if __name__ == "__main__":
    unittest.main()
