use anyhow::{Result, bail};
use hyperrev_loader::boot::{self, Firmware, LoadOption, Variable};
use hyperrev_loader::files::{self, DLL_NAME, EFI_NAME};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use uuid::Uuid;

#[derive(Default)]
struct MemoryFirmware {
    values: BTreeMap<String, Variable>,
    writes: Vec<String>,
    fail_next: Option<String>,
}

impl Firmware for MemoryFirmware {
    fn get(&self, name: &str) -> Result<Option<Variable>> {
        Ok(self.values.get(name).cloned())
    }
    fn put(&mut self, name: &str, value: Option<&Variable>) -> Result<()> {
        self.writes.push(name.into());
        if self.fail_next.as_deref() == Some(name) {
            self.fail_next = None;
            bail!("injected firmware write failure");
        }
        if let Some(value) = value {
            self.values.insert(name.into(), value.clone());
        } else {
            self.values.remove(name);
        }
        Ok(())
    }
}

fn pe(efi: bool) -> Vec<u8> {
    let mut data = vec![0u8; 512];
    data[0..2].copy_from_slice(b"MZ");
    data[60..64].copy_from_slice(&64u32.to_le_bytes());
    data[64..68].copy_from_slice(b"PE\0\0");
    data[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
    data[84..86].copy_from_slice(&240u16.to_le_bytes());
    data[86..88].copy_from_slice(&(if efi { 0x22u16 } else { 0x2022u16 }).to_le_bytes());
    data[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
    data[156..158].copy_from_slice(&(if efi { 10u16 } else { 1u16 }).to_le_bytes());
    data
}

fn reference(esp: Uuid) -> Variable {
    let mut drive = vec![4u8, 1, 42, 0];
    drive.extend(1u32.to_le_bytes());
    drive.extend(2048u64.to_le_bytes());
    drive.extend(1048576u64.to_le_bytes());
    drive.extend(esp.to_bytes_le());
    drive.extend([2, 2]);
    let path: Vec<_> = boot::WINDOWS_PATH
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut device_path = drive;
    device_path.extend([4, 4]);
    device_path.extend(((path.len() + 4) as u16).to_le_bytes());
    device_path.extend(path);
    device_path.extend([0x7f, 0xff, 4, 0]);
    let mut data = Vec::new();
    data.extend(1u32.to_le_bytes());
    data.extend((device_path.len() as u16).to_le_bytes());
    data.extend(
        "Windows Boot Manager"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes),
    );
    data.extend(device_path);
    data.extend(b"WINDOWS\0BCDOBJECT\0");
    Variable {
        attributes: 7,
        data,
    }
}

struct Fixture {
    _temp: TempDir,
    source: PathBuf,
    esp: PathBuf,
    journal: PathBuf,
    guid: Uuid,
    fw: MemoryFirmware,
}

impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-data");
        fs::create_dir_all(&root).unwrap();
        let temp = TempDir::new_in(root).unwrap();
        let source = temp.path().join("source");
        let esp = temp.path().join("esp");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(esp.join("EFI/Microsoft/Boot")).unwrap();
        fs::write(source.join(EFI_NAME), pe(true)).unwrap();
        fs::write(source.join(DLL_NAME), pe(false)).unwrap();
        fs::write(files::windows_manager(&esp), pe(true)).unwrap();
        let guid = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        let mut fw = MemoryFirmware::default();
        fw.values.insert(
            "BootOrder".into(),
            Variable {
                attributes: 7,
                data: vec![0, 0],
            },
        );
        fw.values.insert("Boot0000".into(), reference(guid));
        let journal = temp.path().join("journal.json");
        Self {
            _temp: temp,
            source,
            esp,
            journal,
            guid,
            fw,
        }
    }
    fn plan(&self) -> files::Journal {
        files::plan(&self.fw, &self.source, &self.esp, self.guid, None).unwrap()
    }
    fn installed(&self, name: &str) -> PathBuf {
        files::product_dir(&self.esp).join(name)
    }
}

#[test]
fn reference_drives_a_standalone_firmware_option() {
    let fixture = Fixture::new();
    let old = reference(fixture.guid);
    let new = boot::make_option(&old, fixture.guid).unwrap();
    let parsed = LoadOption::parse(&new.data).unwrap();
    assert_eq!(parsed.file_path().unwrap(), boot::LOADER_PATH);
    assert_eq!(parsed.partition_id().unwrap(), fixture.guid);
    assert_eq!(parsed.description, boot::DESCRIPTION);
    assert_eq!(parsed.attributes, 1);
    assert!(parsed.optional_data.is_empty());
    let original_data = LoadOption::parse(&old.data).unwrap().optional_data;
    assert!(!original_data.is_empty());
    let safe = boot::make_safe_option(&old, fixture.guid).unwrap();
    let safe = LoadOption::parse(&safe.data).unwrap();
    assert_eq!(safe.description, "Safe Windows");
    assert_eq!(safe.file_path().unwrap(), boot::WINDOWS_PATH);
    assert_eq!(safe.optional_data, original_data);
}

#[test]
fn pe_validation_rejects_bootapp_wrong_machine_and_truncation() {
    let mut data = pe(true);
    files::validate_pe(&data, true).unwrap();
    data[156..158].copy_from_slice(&16u16.to_le_bytes());
    assert!(files::validate_pe(&data, true).is_err());
    files::validate_windows_pe(&data).unwrap();
    data[156..158].copy_from_slice(&10u16.to_le_bytes());
    data[68..70].copy_from_slice(&0x14cu16.to_le_bytes());
    assert!(files::validate_pe(&data, true).is_err());
    assert!(files::validate_pe(&data[..100], true).is_err());
    assert!(files::validate_pe(&pe(true), false).is_err());
    files::validate_pe(&pe(false), false).unwrap();
}

#[test]
fn parsing_rejects_malformed_options_and_boot_indices() {
    assert!(LoadOption::parse(&[0; 7]).is_err());
    let mut value = reference(Uuid::nil());
    value.data[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(LoadOption::parse(&value.data).is_err());
    assert!(boot::boot_number("Bootzzzz").is_err());
    assert!(boot::boot_number("Boot00001").is_err());
    assert!(
        boot::index(&Variable {
            attributes: 7,
            data: vec![0, 0, 0]
        })
        .is_err()
    );
    assert!(
        boot::indices(&Variable {
            attributes: 7,
            data: vec![0, 0, 0, 0]
        })
        .is_err()
    );
}

#[test]
fn wrong_esp_is_rejected() {
    let fixture = Fixture::new();
    assert!(boot::make_option(&reference(fixture.guid), Uuid::nil()).is_err());
}

#[test]
fn plan_is_read_only_and_journal_is_create_new() {
    let fixture = Fixture::new();
    let plan = fixture.plan();
    assert!(fixture.fw.writes.is_empty());
    assert!(!files::product_dir(&fixture.esp).exists());
    assert_eq!(plan.boot_name, "Boot0001");
    files::save_new(&fixture.journal, &plan).unwrap();
    assert_eq!(
        files::load(&fixture.journal).unwrap().transaction_id,
        plan.transaction_id
    );
    assert!(files::save_new(&fixture.journal, &plan).is_err());
}

#[test]
fn apply_and_restore_preserve_windows_and_boot_order() {
    let mut fixture = Fixture::new();
    let baseline = fixture.fw.values.clone();
    let manager = files::identity(&files::windows_manager(&fixture.esp)).unwrap();
    let plan = fixture.plan();
    files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    assert_eq!(
        fixture.fw.writes,
        ["Boot0001", "Boot0002", "BootOrder", "BootNext"]
    );
    assert_eq!(
        fixture.fw.get("BootOrder").unwrap().unwrap().data,
        [1, 0, 2, 0, 0, 0]
    );
    assert_eq!(fixture.fw.get("BootNext").unwrap().unwrap().data, [1, 0]);
    assert!(fixture.installed(EFI_NAME).is_file());
    assert_eq!(
        files::identity(&files::windows_manager(&fixture.esp)).unwrap(),
        manager
    );
    files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    assert_eq!(fixture.fw.values, baseline);
    assert!(!files::product_dir(&fixture.esp).exists());
    assert_eq!(
        files::identity(&files::windows_manager(&fixture.esp)).unwrap(),
        manager
    );
    files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
}

#[test]
fn matching_existing_payloads_are_preserved() {
    let mut fixture = Fixture::new();
    fs::create_dir_all(files::product_dir(&fixture.esp)).unwrap();
    for name in [EFI_NAME, DLL_NAME] {
        fs::copy(fixture.source.join(name), fixture.installed(name)).unwrap();
    }
    let plan = fixture.plan();
    files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    assert!(fixture.installed(EFI_NAME).is_file());
    assert!(fixture.installed(DLL_NAME).is_file());
}

#[test]
fn foreign_payload_is_rejected() {
    let fixture = Fixture::new();
    fs::create_dir_all(files::product_dir(&fixture.esp)).unwrap();
    fs::write(fixture.installed(EFI_NAME), b"foreign content").unwrap();
    assert!(
        files::plan(
            &fixture.fw,
            &fixture.source,
            &fixture.esp,
            fixture.guid,
            None
        )
        .is_err()
    );
    assert!(fixture.fw.writes.is_empty());
}

#[test]
fn source_or_windows_changes_stop_apply_before_writes() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    fs::write(fixture.source.join(EFI_NAME), b"changed source").unwrap();
    assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
    fs::write(fixture.source.join(EFI_NAME), pe(true)).unwrap();
    fs::write(
        files::windows_manager(&fixture.esp),
        b"changed windows manager",
    )
    .unwrap();
    assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
}

#[test]
fn pending_boot_next_stops_planning_and_applying() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    fixture.fw.values.insert(
        "BootNext".into(),
        Variable {
            attributes: 7,
            data: vec![2, 0],
        },
    );
    assert!(
        files::plan(
            &fixture.fw,
            &fixture.source,
            &fixture.esp,
            fixture.guid,
            None
        )
        .is_err()
    );
    assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
}

#[test]
fn allocated_option_is_rechecked_before_apply() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    fixture
        .fw
        .values
        .insert(plan.boot_name.clone(), reference(fixture.guid));
    assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
}

#[test]
fn changed_order_stops_restore_without_removing_payloads() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    fixture.fw.writes.clear();
    fixture.fw.values.insert(
        "BootOrder".into(),
        Variable {
            attributes: 7,
            data: vec![0, 0, 1, 0],
        },
    );
    assert!(files::restore(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
    assert!(fixture.installed(EFI_NAME).is_file());
}

#[test]
fn changed_option_or_payload_ownership_stops_restore() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    fixture.fw.writes.clear();
    fixture
        .fw
        .values
        .insert(plan.boot_name.clone(), reference(fixture.guid));
    assert!(files::restore(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
    fixture
        .fw
        .values
        .insert(plan.boot_name.clone(), plan.created_option.clone());
    fs::write(fixture.installed(DLL_NAME), b"foreign replacement").unwrap();
    let error = files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Owned boot entries were removed")
    );
    assert_eq!(
        fixture.fw.writes,
        ["BootNext", "BootOrder", "Boot0001", "Boot0002"]
    );
    assert!(fixture.fw.get("BootNext").unwrap().is_none());
    assert!(fixture.fw.get(&plan.boot_name).unwrap().is_none());
    assert_eq!(
        fs::read(fixture.installed(DLL_NAME)).unwrap(),
        b"foreign replacement"
    );
}

#[test]
fn consumed_boot_next_and_missing_sources_still_allow_restore() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    fixture.fw.values.remove("BootNext");
    fs::remove_file(fixture.source.join(EFI_NAME)).unwrap();
    fs::remove_file(fixture.source.join(DLL_NAME)).unwrap();
    files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    assert!(fixture.fw.get(&plan.boot_name).unwrap().is_none());
    assert!(!files::product_dir(&fixture.esp).exists());
}

#[test]
fn partial_firmware_failure_has_a_working_recovery_journal() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    files::save_new(&fixture.journal, &plan).unwrap();
    fixture.fw.fail_next = Some("BootNext".into());
    assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.get(&plan.boot_name).unwrap().is_some());
    let saved = files::load(&fixture.journal).unwrap();
    files::restore(&mut fixture.fw, &saved, &fixture.esp).unwrap();
    assert!(fixture.fw.get(&plan.boot_name).unwrap().is_none());
    assert!(!fixture.installed(EFI_NAME).exists());
}

#[test]
fn journal_rejects_foreign_paths_options_and_unknown_fields() {
    let fixture = Fixture::new();
    let mut plan = fixture.plan();
    plan.files[0].name = "../Microsoft/Boot/bootmgfw.efi".into();
    assert!(files::validate(&plan).is_err());
    let mut plan = fixture.plan();
    plan.created_option.data.push(0xff);
    assert!(files::validate(&plan).is_err());
    let mut json = serde_json::to_value(fixture.plan()).unwrap();
    json["unknown"] = true.into();
    assert!(serde_json::from_value::<files::Journal>(json).is_err());
}

#[test]
fn inspect_reports_uefi_paths_without_mutation() {
    let fixture = Fixture::new();
    let snapshot = boot::inspect(&fixture.fw).unwrap();
    assert_eq!(snapshot.boot_order, [0]);
    assert_eq!(
        snapshot.options[0].file_path.as_deref(),
        Some(boot::WINDOWS_PATH)
    );
    assert!(fixture.fw.writes.is_empty());
}

#[test]
fn image_and_journal_helpers_require_absolute_paths() {
    assert!(files::identity(Path::new("relative.efi")).is_err());
    assert!(files::load(Path::new("relative.json")).is_err());
}

#[test]
fn interrupted_empty_and_short_stages_are_recoverable() {
    for size in [0, 113] {
        let mut fixture = Fixture::new();
        let plan = fixture.plan();
        fs::create_dir_all(files::product_dir(&fixture.esp)).unwrap();
        let staged = files::product_dir(&fixture.esp).join(format!(
            ".hyperrev-{}-{}.stage",
            plan.transaction_id, EFI_NAME
        ));
        fs::write(&staged, &pe(true)[..size]).unwrap();
        files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
        assert!(!staged.exists());
        assert!(!files::product_dir(&fixture.esp).exists());
    }
}

#[test]
fn complete_stage_is_recoverable_without_the_source() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    fs::create_dir_all(files::product_dir(&fixture.esp)).unwrap();
    let staged = files::product_dir(&fixture.esp).join(format!(
        ".hyperrev-{}-{}.stage",
        plan.transaction_id, EFI_NAME
    ));
    fs::write(&staged, pe(true)).unwrap();
    fs::remove_file(fixture.source.join(EFI_NAME)).unwrap();
    files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    assert!(!staged.exists());
}

#[test]
fn unknown_partial_stage_is_retained_after_owned_boot_is_disarmed() {
    for missing_source in [false, true] {
        let mut fixture = Fixture::new();
        let plan = fixture.plan();
        files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
        let staged = files::product_dir(&fixture.esp).join(format!(
            ".hyperrev-{}-{}.stage",
            plan.transaction_id, EFI_NAME
        ));
        if missing_source {
            fs::write(&staged, &pe(true)[..100]).unwrap();
            fs::remove_file(fixture.source.join(EFI_NAME)).unwrap();
        } else {
            fs::write(&staged, b"foreign partial bytes").unwrap();
        }
        let error = files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Owned boot entries were removed")
        );
        assert!(fixture.fw.get("BootNext").unwrap().is_none());
        assert!(fixture.fw.get(&plan.boot_name).unwrap().is_none());
        assert!(staged.exists());
    }
}

#[test]
fn every_partial_dual_boot_write_can_restore_the_original_firmware() {
    for phase in ["Boot0001", "Boot0002", "BootOrder", "BootNext"] {
        let mut fixture = Fixture::new();
        let original = fixture.fw.values.clone();
        let plan = fixture.plan();
        fixture.fw.fail_next = Some(phase.into());
        assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
        files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
        assert_eq!(fixture.fw.values, original, "Restore after failed {phase}");
        assert!(!fixture.installed(EFI_NAME).exists());
    }
}

#[test]
fn a_safe_windows_option_claimed_after_planning_is_preserved() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    fixture
        .fw
        .values
        .insert(plan.safe_name.clone(), reference(fixture.guid));
    assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
    assert!(!files::product_dir(&fixture.esp).exists());
}

#[test]
fn oversized_journal_is_rejected_before_creating_a_file() {
    let fixture = Fixture::new();
    let mut plan = fixture.plan();
    plan.reference_before.data.extend(vec![0x55; 200_000]);
    plan.safe_option = boot::make_safe_option(&plan.reference_before, fixture.guid).unwrap();
    files::validate(&plan).unwrap();
    assert!(files::save_new(&fixture.journal, &plan).is_err());
    assert!(!fixture.journal.exists());
}

#[test]
fn a_failed_original_order_restore_keeps_both_boot_entries() {
    let mut fixture = Fixture::new();
    let original = fixture.fw.values.clone();
    let plan = fixture.plan();
    files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    fixture.fw.fail_next = Some("BootOrder".into());
    assert!(files::restore(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.get("BootNext").unwrap().is_none());
    assert!(fixture.fw.get(&plan.boot_name).unwrap().is_some());
    assert!(fixture.fw.get(&plan.safe_name).unwrap().is_some());
    assert!(fixture.installed(EFI_NAME).is_file());
    files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    assert_eq!(fixture.fw.values, original);
}

#[test]
fn another_pending_boot_request_stops_restore_without_replacing_it() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    files::apply(&mut fixture.fw, &plan, &fixture.esp).unwrap();
    let pending = Variable {
        attributes: 7,
        data: vec![9, 0],
    };
    fixture.fw.values.insert("BootNext".into(), pending.clone());
    fixture.fw.writes.clear();
    assert!(files::restore(&mut fixture.fw, &plan, &fixture.esp).is_err());
    assert!(fixture.fw.writes.is_empty());
    assert_eq!(fixture.fw.get("BootNext").unwrap(), Some(pending));
}

#[test]
fn a_late_matching_destination_is_retained_when_apply_never_published_it() {
    let mut fixture = Fixture::new();
    let original = fixture.fw.values.clone();
    let plan = fixture.plan();
    fs::create_dir_all(files::product_dir(&fixture.esp)).unwrap();
    fs::copy(fixture.source.join(EFI_NAME), fixture.installed(EFI_NAME)).unwrap();
    assert!(files::apply(&mut fixture.fw, &plan, &fixture.esp).is_err());
    let error = files::restore(&mut fixture.fw, &plan, &fixture.esp).unwrap_err();
    assert!(error.to_string().contains("Publication receipt is absent"));
    assert!(fixture.installed(EFI_NAME).is_file());
    assert_eq!(fixture.fw.values, original);
}

#[test]
fn full_setup_plans_installs_and_reuses_a_verified_installation() {
    let mut fixture = Fixture::new();
    let (plan, reused) = files::full_setup(
        &mut fixture.fw,
        &fixture.source,
        &fixture.esp,
        fixture.guid,
        &fixture.journal,
        None,
    )
    .unwrap();
    assert!(!reused);
    assert_eq!(
        files::load(&fixture.journal).unwrap().transaction_id,
        plan.transaction_id
    );
    assert_eq!(
        fixture.fw.get("BootOrder").unwrap(),
        Some(plan.boot_order_after.clone())
    );
    fixture.fw.writes.clear();
    let (second, reused) = files::full_setup(
        &mut fixture.fw,
        &fixture.source,
        &fixture.esp,
        fixture.guid,
        &fixture.journal,
        None,
    )
    .unwrap();
    assert!(reused);
    assert_eq!(second.transaction_id, plan.transaction_id);
    assert!(fixture.fw.writes.is_empty());
}

#[test]
fn full_setup_recovers_partial_firmware_writes_without_manual_steps() {
    for phase in ["Boot0001", "Boot0002", "BootOrder", "BootNext"] {
        let mut fixture = Fixture::new();
        fixture.fw.fail_next = Some(phase.into());
        assert!(
            files::full_setup(
                &mut fixture.fw,
                &fixture.source,
                &fixture.esp,
                fixture.guid,
                &fixture.journal,
                None
            )
            .is_err()
        );
        let previous = files::load(&fixture.journal).unwrap();
        let (installed, reused) = files::full_setup(
            &mut fixture.fw,
            &fixture.source,
            &fixture.esp,
            fixture.guid,
            &fixture.journal,
            None,
        )
        .unwrap();
        if phase == "BootNext" {
            // Both persistent entries and their default order already landed.
            assert!(reused);
            assert_eq!(installed.transaction_id, previous.transaction_id);
        } else {
            assert!(!reused);
            assert_ne!(installed.transaction_id, previous.transaction_id);
            assert!(
                fixture
                    .journal
                    .with_file_name(format!(
                        "boot-install-{}-restored.json",
                        previous.transaction_id
                    ))
                    .is_file()
            );
        }
        assert_eq!(
            fixture.fw.get("BootOrder").unwrap(),
            Some(installed.boot_order_after)
        );
    }
}

#[test]
fn full_setup_updates_owned_payloads_and_preserves_recovery_history() {
    let mut fixture = Fixture::new();
    let (previous, _) = files::full_setup(
        &mut fixture.fw,
        &fixture.source,
        &fixture.esp,
        fixture.guid,
        &fixture.journal,
        None,
    )
    .unwrap();
    let mut new_image = pe(true);
    new_image[511] = 0x42;
    fs::write(fixture.source.join(EFI_NAME), &new_image).unwrap();
    let (installed, reused) = files::full_setup(
        &mut fixture.fw,
        &fixture.source,
        &fixture.esp,
        fixture.guid,
        &fixture.journal,
        None,
    )
    .unwrap();
    assert!(!reused);
    assert_ne!(previous.transaction_id, installed.transaction_id);
    assert_eq!(fs::read(fixture.installed(EFI_NAME)).unwrap(), new_image);
    assert!(
        fixture
            .journal
            .with_file_name(format!(
                "boot-install-{}-restored.json",
                previous.transaction_id
            ))
            .is_file()
    );
}

#[test]
fn full_setup_keeps_existing_firmware_when_new_source_validation_fails() {
    let mut fixture = Fixture::new();
    let (previous, _) = files::full_setup(
        &mut fixture.fw,
        &fixture.source,
        &fixture.esp,
        fixture.guid,
        &fixture.journal,
        None,
    )
    .unwrap();
    let expected = fixture.fw.values.clone();
    fixture.fw.writes.clear();
    fs::write(fixture.source.join(EFI_NAME), b"invalid new image").unwrap();
    assert!(
        files::full_setup(
            &mut fixture.fw,
            &fixture.source,
            &fixture.esp,
            fixture.guid,
            &fixture.journal,
            None
        )
        .is_err()
    );
    assert_eq!(fixture.fw.values, expected);
    assert!(fixture.fw.writes.is_empty());
    assert_eq!(
        files::load(&fixture.journal).unwrap().transaction_id,
        previous.transaction_id
    );
}

#[test]
fn publishing_never_replaces_a_destination_that_appeared_during_staging() {
    let fixture = Fixture::new();
    let staged = fixture.source.join("staged.efi");
    let destination = fixture.source.join("arrived.efi");
    fs::write(&staged, b"our staged image").unwrap();
    fs::write(&destination, b"another owner arrived").unwrap();
    assert!(hyperrev_loader::promote::publish_new(&staged, &destination).is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"another owner arrived");
    assert_eq!(fs::read(&staged).unwrap(), b"our staged image");
}
