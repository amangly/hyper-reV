use crate::{boot, files, platform, stock};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct SetupInput {
    pub source: PathBuf,
    pub esp: Option<PathBuf>,
    pub journal: PathBuf,
    pub reference: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Inspect,
    Setup,
    Plan,
    Apply,
    Restore,
}

pub fn default_input() -> SetupInput {
    let current = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| current.clone());
    let sibling_source = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let source = sibling_source
        .filter(|folder| {
            folder.join(files::EFI_NAME).is_file() && folder.join(files::DLL_NAME).is_file()
        })
        .unwrap_or_else(|| current.join("build").join("Release"));
    SetupInput {
        source,
        esp: None,
        journal: local.join("hyper-reV").join("boot-install.json"),
        reference: None,
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

pub fn perform(operation: Operation, input: SetupInput) -> Result<String> {
    let machine = platform::machine_info();
    if matches!(operation, Operation::Inspect) {
        let firmware = platform::NativeFirmware::open().and_then(|fw| boot::inspect(&fw));
        let output = match firmware {
            Ok(snapshot) => {
                json!({"operation": "inspect", "machine": machine, "firmware": snapshot, "restart_scheduled": false})
            }
            Err(error) => {
                json!({"operation": "inspect", "machine": machine, "firmware_error": format!("{error:#}"), "restart_scheduled": false})
            }
        };
        return Ok(serde_json::to_string_pretty(&output)?);
    }
    ensure!(
        machine.administrator,
        "Run the loader as administrator for boot setup"
    );
    ensure!(
        machine.firmware.eq_ignore_ascii_case("UEFI"),
        "Boot setup requires Windows already running in UEFI mode"
    );
    if matches!(operation, Operation::Apply | Operation::Setup) {
        ensure!(
            machine.secure_boot == Some(false),
            "This unsigned EFI setup requires Secure Boot to be verified off; firmware trust policy stays unchanged"
        );
        ensure!(
            machine.hyperv_available,
            "Windows Hyper-V binaries are absent; boot activation requires Hyper-V already installed"
        );
    }
    let journal_path = absolute(&input.journal)?;
    let _lock = platform::MutationLock::acquire()?;
    let mount = platform::EspMount::open(input.esp.as_deref())?;
    let esp = mount.root();
    let actual_guid: Uuid = platform::partition_id(esp)?
        .parse()
        .context("Parse ESP partition identity")?;
    let scope = platform::volume_relative_path(&files::product_dir(esp))?;
    ensure!(
        scope.eq_ignore_ascii_case(r"\EFI\hyper-reV"),
        "Setup target differs from the dedicated EFI directory"
    );
    let mut firmware = platform::NativeFirmware::open()?;
    let report = match operation {
        Operation::Inspect => unreachable!(),
        Operation::Setup => {
            let source = absolute(&input.source)?;
            files::source_identities(&source)?;
            let windows = stock::prepare(esp, true)?;
            let (journal, already_configured) = files::full_setup(
                &mut firmware,
                &source,
                esp,
                actual_guid,
                &journal_path,
                input.reference.as_deref(),
            )?;
            json!({"operation": "setup", "state": "installed", "already_configured": already_configured, "journal_path": journal_path, "hyperrev_option": journal.boot_name, "safe_windows_option": journal.safe_name, "boot_order": boot::indices(&journal.boot_order_after)?, "windows_boot_manager_unchanged": windows.restored_from.is_none(), "windows_boot_manager": windows, "restart_scheduled": false, "message": if already_configured { "hyper-reV and Safe Windows are already configured; firmware was left unchanged." } else { "Full setup finished. hyper-reV and Safe Windows are installed. Restart Windows manually when ready." }})
        }
        Operation::Plan => {
            stock::prepare(esp, false)?;
            let source = absolute(&input.source)?;
            let journal = files::plan(
                &firmware,
                &source,
                esp,
                actual_guid,
                input.reference.as_deref(),
            )?;
            files::save_new(&journal_path, &journal)?;
            json!({"operation": "plan", "state": "planned", "journal_path": journal_path, "machine": machine, "plan": journal, "boot_order_unchanged": true, "restart_scheduled": false})
        }
        Operation::Apply => {
            stock::prepare(esp, false)?;
            let journal = files::load(&journal_path)?;
            ensure!(
                actual_guid == journal.esp_guid,
                "Selected ESP differs from the journal's partition GUID"
            );
            let operation = files::apply(&mut firmware, &journal, esp);
            operation.with_context(|| {
                format!(
                    "Setup stopped; retain {} and use Restore to recover any owned partial changes",
                    journal_path.display()
                )
            })?;
            json!({"operation": "apply", "state": "installed", "journal_path": journal_path, "esp_guid": actual_guid, "hyperrev_option": journal.boot_name, "safe_windows_option": journal.safe_name, "boot_next": journal.boot_number, "boot_order": boot::indices(&journal.boot_order_after)?, "original_boot_entries_preserved": true, "windows_boot_manager_unchanged": true, "restart_scheduled": false, "message": "Persistent hyper-reV and Safe Windows entries verified. Restart manually; select Safe Windows in the firmware boot menu to start stock Windows directly."})
        }
        Operation::Restore => {
            let journal = files::load(&journal_path)?;
            ensure!(
                actual_guid == journal.esp_guid,
                "Selected ESP differs from the journal's partition GUID"
            );
            files::restore(&mut firmware, &journal, esp)?;
            json!({"operation": "restore", "state": "restored", "journal_path": journal_path, "hyperrev_option": journal.boot_name, "safe_windows_option": journal.safe_name, "original_boot_order_restored": true, "windows_boot_manager_unchanged": true, "restart_scheduled": false, "message": "Owned dual-boot entries removed and original firmware order restored. Existing matching files were preserved."})
        }
    };
    Ok(serde_json::to_string_pretty(&report)?)
}
