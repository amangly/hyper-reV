#![cfg(windows)]

use hyperrev_loader::{boot, files, platform};

#[test]
#[ignore = "Requires elevated Windows; reads firmware and temporarily mounts the system ESP"]
fn inspect_native_esp_without_changing_boot_files_or_firmware() {
    let _lock = platform::MutationLock::acquire().unwrap();
    let firmware = platform::NativeFirmware::open().unwrap();
    let before = boot::inspect(&firmware).unwrap();
    {
        let mount = platform::EspMount::open(None).unwrap();
        let guid: uuid::Uuid = platform::partition_id(mount.root())
            .unwrap()
            .parse()
            .unwrap();
        assert!(!guid.is_nil());
        let relative = platform::volume_relative_path(&files::product_dir(mount.root())).unwrap();
        assert!(relative.eq_ignore_ascii_case(r"\EFI\hyper-reV"));
        println!(
            "ESP root: {}; GPT identity: {guid}; product path: {relative}",
            mount.root().display()
        );
    }
    let after = boot::inspect(&firmware).unwrap();
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(after).unwrap()
    );
}
