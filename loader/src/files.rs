use crate::boot::{self, Firmware, Variable};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

pub const EFI_NAME: &str = "uefi-boot-standalone.efi";
pub const DLL_NAME: &str = "hyperv-attachment.dll";
const MAX_IMAGE_SIZE: u64 = 64 * 1024 * 1024;
const MAX_JOURNAL_SIZE: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedFile {
    pub name: String,
    pub source: PathBuf,
    pub identity: Identity,
    pub existed_before: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Planned,
    Applied,
    Restored,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub schema: u32,
    pub transaction_id: Uuid,
    pub phase: Phase,
    pub esp_guid: Uuid,
    pub esp_hint: PathBuf,
    pub boot_number: u16,
    pub boot_name: String,
    pub safe_number: u16,
    pub safe_name: String,
    pub safe_option: Variable,
    pub boot_order_after: Variable,
    pub reference_name: String,
    pub reference_before: Variable,
    pub boot_order_before: Variable,
    pub boot_next_before: Option<Variable>,
    pub created_option: Variable,
    pub windows_boot_manager: Identity,
    pub product_directory_existed: bool,
    pub files: Vec<PlannedFile>,
}

pub fn reject_links(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "Expected absolute path: {}",
        path.display()
    );
    ensure!(
        !path
            .components()
            .any(|component| matches!(component, Component::ParentDir)),
        "Parent path traversal is unsupported"
    );
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                ensure!(
                    !metadata.file_type().is_symlink(),
                    "Symbolic link in path: {}",
                    ancestor.display()
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "Reparse point in path: {}",
                        ancestor.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("Inspect path {}", ancestor.display()));
            }
        }
    }
    Ok(())
}

fn read_image(path: &Path) -> Result<Vec<u8>> {
    reject_links(path)?;
    let file = fs::File::open(path).with_context(|| format!("Open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_IMAGE_SIZE,
        "Image must be a regular file of at most 64 MiB: {}",
        path.display()
    );
    let mut data = Vec::new();
    file.take(MAX_IMAGE_SIZE + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() as u64 == metadata.len(),
        "Image changed while reading: {}",
        path.display()
    );
    Ok(data)
}

pub fn identity(path: &Path) -> Result<Identity> {
    let data = read_image(path)?;
    Ok(bytes_identity(&data))
}

fn bytes_identity(data: &[u8]) -> Identity {
    Identity {
        bytes: data.len() as u64,
        sha256: format!("{:x}", Sha256::digest(data)),
    }
}

fn pe_headers(data: &[u8]) -> Result<(usize, usize)> {
    ensure!(
        data.len() >= 64 && &data[..2] == b"MZ",
        "Expected a PE executable"
    );
    let pe = u32::from_le_bytes(data[60..64].try_into()?) as usize;
    let header_end = pe.checked_add(24).context("PE header offset overflow")?;
    ensure!(
        header_end <= data.len() && &data[pe..pe + 4] == b"PE\0\0",
        "Invalid PE signature"
    );
    ensure!(
        u16::from_le_bytes(data[pe + 4..pe + 6].try_into()?) == 0x8664,
        "Expected an x64 image"
    );
    let optional_size = u16::from_le_bytes(data[pe + 20..pe + 22].try_into()?) as usize;
    ensure!(
        optional_size >= 112 && header_end + optional_size <= data.len(),
        "Truncated PE32+ header"
    );
    ensure!(
        u16::from_le_bytes(data[header_end..header_end + 2].try_into()?) == 0x20b,
        "Expected PE32+"
    );
    Ok((pe, header_end))
}

pub fn validate_windows_pe(data: &[u8]) -> Result<()> {
    let (_, optional) = pe_headers(data)?;
    let subsystem = u16::from_le_bytes(data[optional + 68..optional + 70].try_into()?);
    ensure!(
        matches!(subsystem, 10 | 16),
        "Expected a Windows EFI boot-manager image"
    );
    Ok(())
}

pub fn validate_pe(data: &[u8], efi: bool) -> Result<()> {
    let (pe, header_end) = pe_headers(data)?;
    if efi {
        ensure!(
            u16::from_le_bytes(data[header_end + 68..header_end + 70].try_into()?) == 10,
            "Expected EFI_APPLICATION (subsystem 10), rather than Windows BOOTAPP"
        );
    } else {
        ensure!(
            u16::from_le_bytes(data[pe + 22..pe + 24].try_into()?) & 0x2000 != 0,
            "Attachment image requires the DLL flag"
        );
    }
    Ok(())
}

pub fn source_identities(source: &Path) -> Result<Vec<Identity>> {
    let mut identities = Vec::new();
    for name in [EFI_NAME, DLL_NAME] {
        let bytes = read_image(&source.join(name))?;
        validate_pe(&bytes, name == EFI_NAME).with_context(|| format!("Validate {name}"))?;
        identities.push(bytes_identity(&bytes));
    }
    Ok(identities)
}

pub fn product_dir(esp: &Path) -> PathBuf {
    esp.join("EFI").join("hyper-reV")
}
pub fn windows_manager(esp: &Path) -> PathBuf {
    esp.join("EFI")
        .join("Microsoft")
        .join("Boot")
        .join("bootmgfw.efi")
}

pub fn plan(
    fw: &impl Firmware,
    source: &Path,
    esp: &Path,
    esp_guid: Uuid,
    reference: Option<&str>,
) -> Result<Journal> {
    reject_links(source)?;
    reject_links(esp)?;
    ensure!(
        fw.get("BootNext")?.is_none(),
        "Another one-time boot request already owns BootNext"
    );
    let (reference_name, reference_before, order) = boot::find_reference(fw, esp_guid, reference)?;
    let product = product_dir(esp);
    reject_links(&product)?;
    let manager = windows_manager(esp);
    let manager_bytes = read_image(&manager)?;
    validate_windows_pe(&manager_bytes).context("Validate the existing Windows boot manager")?;
    let mut files = Vec::new();
    for name in [EFI_NAME, DLL_NAME] {
        let path = source.join(name);
        let bytes = read_image(&path)?;
        validate_pe(&bytes, name == EFI_NAME).with_context(|| format!("Validate {name}"))?;
        let expected = bytes_identity(&bytes);
        let destination = product.join(name);
        let exists = destination.try_exists()?;
        if exists {
            ensure!(
                identity(&destination)? == expected,
                "Existing {name} differs; restore its previous installation before replacing it"
            );
        }
        files.push(PlannedFile {
            name: name.into(),
            source: path.canonicalize()?,
            identity: expected,
            existed_before: exists,
        });
    }
    let number = boot::allocate(fw, &order)?;
    let safe_number = boot::allocate_excluding(fw, &order, &[number])?;
    let boot_order_after = dual_boot_order(&order, number, safe_number)?;
    let journal = Journal {
        schema: 2,
        transaction_id: Uuid::new_v4(),
        phase: Phase::Planned,
        esp_guid,
        esp_hint: esp.to_path_buf(),
        boot_number: number,
        boot_name: format!("Boot{number:04X}"),
        safe_number,
        safe_name: format!("Boot{safe_number:04X}"),
        safe_option: boot::make_safe_option(&reference_before, esp_guid)?,
        boot_order_after,
        created_option: boot::make_option(&reference_before, esp_guid)?,
        reference_name,
        reference_before,
        boot_order_before: order,
        boot_next_before: None,
        windows_boot_manager: bytes_identity(&manager_bytes),
        product_directory_existed: product.is_dir(),
        files,
    };
    validate(&journal)?;
    Ok(journal)
}

fn dual_boot_order(original: &Variable, hyperrev: u16, safe: u16) -> Result<Variable> {
    let mut order = vec![hyperrev, safe];
    order.extend(boot::indices(original)?);
    Ok(Variable {
        attributes: original.attributes,
        data: order.into_iter().flat_map(u16::to_le_bytes).collect(),
    })
}

pub fn validate(journal: &Journal) -> Result<()> {
    ensure!(
        journal.schema == 2 && !journal.transaction_id.is_nil(),
        "Unsupported installation journal"
    );
    ensure!(
        journal.boot_name == format!("Boot{:04X}", journal.boot_number),
        "Journal boot identity differs"
    );
    ensure!(
        journal.safe_name == format!("Boot{:04X}", journal.safe_number)
            && journal.safe_number != journal.boot_number,
        "Journal Safe Windows identity differs"
    );
    let order = boot::indices(&journal.boot_order_before)?;
    ensure!(
        !order.contains(&journal.boot_number) && !order.contains(&journal.safe_number),
        "Journal boot number belongs to the original boot order"
    );
    ensure!(
        journal.boot_order_after
            == dual_boot_order(
                &journal.boot_order_before,
                journal.boot_number,
                journal.safe_number
            )?,
        "Journal boot order differs from the original entries with the owned prefix"
    );
    ensure!(
        boot::make_safe_option(&journal.reference_before, journal.esp_guid)? == journal.safe_option,
        "Journal Safe Windows option differs from the stock Windows reference"
    );
    ensure!(
        order.contains(&boot::boot_number(&journal.reference_name)?),
        "Journal reference is absent from the original boot order"
    );
    ensure!(
        journal.boot_next_before.is_none(),
        "Journal would replace an existing BootNext request"
    );
    ensure!(
        boot::make_option(&journal.reference_before, journal.esp_guid)? == journal.created_option,
        "Journal boot option differs from the reference-derived path"
    );
    ensure!(
        journal.files.len() == 2,
        "Journal requires exactly two payload files"
    );
    for (file, name) in journal.files.iter().zip([EFI_NAME, DLL_NAME]) {
        ensure!(
            file.name == name && file.source.is_absolute(),
            "Invalid payload path in journal"
        );
        validate_identity(&file.identity)?;
    }
    validate_identity(&journal.windows_boot_manager)
}

fn validate_identity(identity: &Identity) -> Result<()> {
    ensure!(
        identity.bytes >= 64
            && identity.bytes <= MAX_IMAGE_SIZE
            && identity.sha256.len() == 64
            && identity
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "Invalid SHA-256 file identity"
    );
    Ok(())
}

fn compare(fw: &impl Firmware, name: &str, expected: Option<&Variable>) -> Result<()> {
    ensure!(
        fw.get(name)?.as_ref() == expected,
        "Firmware state changed: {name}"
    );
    Ok(())
}

fn verify_scope(journal: &Journal, esp: &Path) -> Result<()> {
    validate(journal)?;
    reject_links(esp)?;
    reject_links(&product_dir(esp))?;
    ensure!(
        identity(&windows_manager(esp))? == journal.windows_boot_manager,
        "The stock Windows boot manager changed since planning"
    );
    Ok(())
}

pub fn installation_matches(
    fw: &impl Firmware,
    journal: &Journal,
    esp: &Path,
    source: &Path,
) -> Result<bool> {
    verify_scope(journal, esp)?;
    if fw.get("BootOrder")?.as_ref() != Some(&journal.boot_order_after)
        || fw.get(&journal.boot_name)?.as_ref() != Some(&journal.created_option)
        || fw.get(&journal.safe_name)?.as_ref() != Some(&journal.safe_option)
    {
        return Ok(false);
    }
    if let Some(next) = fw.get("BootNext")?
        && boot::index(&next)? != journal.boot_number
    {
        return Ok(false);
    }
    let identities = source_identities(source)?;
    for (file, current_source) in journal.files.iter().zip(identities) {
        let target = product_dir(esp).join(&file.name);
        if current_source != file.identity
            || !target.try_exists()?
            || identity(&target)? != file.identity
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Save recovery state and install both entries, or retain a verified matching installation.
pub fn full_setup(
    fw: &mut impl Firmware,
    source: &Path,
    esp: &Path,
    esp_guid: Uuid,
    journal_path: &Path,
    reference: Option<&str>,
) -> Result<(Journal, bool)> {
    source_identities(source)?;
    if journal_path.try_exists()? {
        let previous = load(journal_path)?;
        ensure!(
            previous.esp_guid == esp_guid,
            "Saved installation belongs to another ESP"
        );
        if installation_matches(fw, &previous, esp, source)? {
            return Ok((previous, true));
        }
        let expected_journal = identity(journal_path)?;
        restore(fw, &previous, esp)?;
        let archive = journal_path.with_file_name(format!(
            "boot-install-{}-restored.json",
            previous.transaction_id
        ));
        ensure!(
            identity(journal_path)? == expected_journal,
            "Recovery journal changed before archival"
        );
        reject_links(&archive)?;
        crate::promote::publish_new(journal_path, &archive)?;
    }
    let journal = plan(fw, source, esp, esp_guid, reference)?;
    save_new(journal_path, &journal)?;
    apply(fw, &journal, esp).with_context(|| {
        format!(
            "Full setup stopped; retain {} and use Restore to recover owned partial changes",
            journal_path.display()
        )
    })?;
    Ok((journal, false))
}

pub fn apply(fw: &mut impl Firmware, journal: &Journal, esp: &Path) -> Result<()> {
    ensure!(
        journal.phase == Phase::Planned,
        "Apply requires a new plan; restore an existing installation first"
    );
    verify_scope(journal, esp)?;
    compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
    compare(fw, "BootNext", None)?;
    compare(fw, &journal.reference_name, Some(&journal.reference_before))?;
    compare(fw, &journal.boot_name, None)?;
    compare(fw, &journal.safe_name, None)?;
    let directory = product_dir(esp);
    for file in &journal.files {
        ensure!(
            identity(&file.source)? == file.identity,
            "Source image changed: {}",
            file.source.display()
        );
        let target = directory.join(&file.name);
        if file.existed_before {
            ensure!(
                identity(&target)? == file.identity,
                "Existing payload changed: {}",
                target.display()
            );
        } else {
            ensure!(
                !target.try_exists()?,
                "Another installation now owns {}",
                target.display()
            );
            ensure!(
                !receipt_path(journal, esp, file).try_exists()?,
                "A publication receipt already exists; use restore"
            );
        }
    }
    fs::create_dir_all(&directory)?;
    reject_links(&directory)?;
    for file in &journal.files {
        if file.existed_before {
            continue;
        }
        let target = directory.join(&file.name);
        let temporary = staged_path(journal, esp, file);
        ensure!(
            !temporary.try_exists()?,
            "A staged transaction already exists; use restore"
        );
        let bytes = read_image(&file.source)?;
        ensure!(
            bytes_identity(&bytes) == file.identity,
            "Source image changed before staging"
        );
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        drop(output);
        ensure!(
            identity(&temporary)? == file.identity,
            "Staged image readback failed"
        );
        ensure!(!target.try_exists()?, "Destination appeared during staging");
        crate::promote::publish_new(&temporary, &target)?;
        ensure!(
            identity(&target)? == file.identity,
            "Installed image readback failed"
        );
        write_publication_receipt(journal, esp, file)?;
    }
    compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
    compare(fw, "BootNext", None)?;
    compare(fw, &journal.reference_name, Some(&journal.reference_before))?;
    compare(fw, &journal.boot_name, None)?;
    compare(fw, &journal.safe_name, None)?;
    fw.put(&journal.boot_name, Some(&journal.created_option))?;
    compare(fw, &journal.boot_name, Some(&journal.created_option))?;
    compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
    compare(fw, &journal.safe_name, None)?;
    fw.put(&journal.safe_name, Some(&journal.safe_option))?;
    compare(fw, &journal.safe_name, Some(&journal.safe_option))?;
    compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
    compare(fw, "BootNext", None)?;
    fw.put("BootOrder", Some(&journal.boot_order_after))?;
    compare(fw, "BootOrder", Some(&journal.boot_order_after))?;
    compare(fw, "BootNext", None)?;
    let next = Variable {
        attributes: 7,
        data: journal.boot_number.to_le_bytes().to_vec(),
    };
    fw.put("BootNext", Some(&next))?;
    compare(fw, "BootNext", Some(&next))?;
    compare(fw, "BootOrder", Some(&journal.boot_order_after))?;
    compare(fw, &journal.boot_name, Some(&journal.created_option))?;
    compare(fw, &journal.safe_name, Some(&journal.safe_option))?;
    ensure!(
        identity(&windows_manager(esp))? == journal.windows_boot_manager,
        "Windows boot manager identity changed during installation"
    );
    Ok(())
}

fn staged_path(journal: &Journal, esp: &Path, file: &PlannedFile) -> PathBuf {
    product_dir(esp).join(format!(
        ".hyperrev-{}-{}.stage",
        journal.transaction_id, file.name
    ))
}

fn receipt_path(journal: &Journal, esp: &Path, file: &PlannedFile) -> PathBuf {
    product_dir(esp).join(format!(
        ".hyperrev-{}-{}.owned",
        journal.transaction_id, file.name
    ))
}

fn receipt_bytes(journal: &Journal, file: &PlannedFile) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n",
        journal.transaction_id, file.name, file.identity.bytes, file.identity.sha256
    )
    .into_bytes()
}

fn write_publication_receipt(journal: &Journal, esp: &Path, file: &PlannedFile) -> Result<()> {
    let path = receipt_path(journal, esp, file);
    reject_links(&path)?;
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    receipt.write_all(&receipt_bytes(journal, file))?;
    receipt.sync_all()?;
    Ok(())
}

fn remove_published(journal: &Journal, esp: &Path, file: &PlannedFile) -> Result<()> {
    let target = product_dir(esp).join(&file.name);
    let receipt = receipt_path(journal, esp, file);
    if !receipt.try_exists()? {
        ensure!(
            !target.try_exists()?,
            "Publication receipt is absent; the destination's ownership is unproven"
        );
        return Ok(());
    }
    let expected_receipt = receipt_bytes(journal, file);
    ensure!(
        read_image(&receipt)? == expected_receipt,
        "Publication receipt differs or is incomplete"
    );
    remove_owned(&target, &file.identity)?;
    ensure!(
        read_image(&receipt)? == expected_receipt,
        "Publication receipt changed before cleanup"
    );
    fs::remove_file(&receipt)?;
    Ok(())
}

pub fn restore(fw: &mut impl Firmware, journal: &Journal, esp: &Path) -> Result<()> {
    verify_scope(journal, esp)?;
    let current_order = fw
        .get("BootOrder")?
        .context("Firmware BootOrder is absent")?;
    ensure!(
        current_order == journal.boot_order_before || current_order == journal.boot_order_after,
        "Firmware boot order changed outside this installation"
    );
    compare(fw, &journal.reference_name, Some(&journal.reference_before))?;
    let current = fw.get(&journal.boot_name)?;
    ensure!(
        current
            .as_ref()
            .is_none_or(|value| value == &journal.created_option),
        "Boot option now belongs to another installation"
    );
    let safe = fw.get(&journal.safe_name)?;
    ensure!(
        safe.as_ref()
            .is_none_or(|value| value == &journal.safe_option),
        "Safe Windows option now belongs to another installation"
    );
    let next = fw.get("BootNext")?;
    let expected_next = Variable {
        attributes: 7,
        data: journal.boot_number.to_le_bytes().to_vec(),
    };
    ensure!(
        next.as_ref().is_none_or(|value| value == &expected_next),
        "Another one-time boot request owns BootNext"
    );
    compare(fw, &journal.boot_name, current.as_ref())?;
    compare(fw, &journal.safe_name, safe.as_ref())?;
    compare(fw, "BootNext", next.as_ref())?;
    if next.is_some() {
        fw.put("BootNext", None)?;
        compare(fw, "BootNext", None)?;
    }
    if current_order != journal.boot_order_before {
        compare(fw, "BootOrder", Some(&journal.boot_order_after))?;
        compare(fw, "BootNext", None)?;
        fw.put("BootOrder", Some(&journal.boot_order_before))?;
        compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
    }
    if current.is_some() {
        compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
        compare(fw, "BootNext", None)?;
        compare(fw, &journal.boot_name, Some(&journal.created_option))?;
        fw.put(&journal.boot_name, None)?;
        compare(fw, &journal.boot_name, None)?;
    }
    if safe.is_some() {
        compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
        compare(fw, "BootNext", None)?;
        compare(fw, &journal.safe_name, Some(&journal.safe_option))?;
        fw.put(&journal.safe_name, None)?;
        compare(fw, &journal.safe_name, None)?;
    }
    let mut retained = Vec::new();
    for file in &journal.files {
        compare(fw, "BootNext", None)?;
        compare(fw, &journal.boot_name, None)?;
        compare(fw, &journal.safe_name, None)?;
        compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
        if !file.existed_before {
            let target = product_dir(esp).join(&file.name);
            if let Err(error) = remove_published(journal, esp, file) {
                retained.push(format!("{}: {error:#}", target.display()));
            }
        }
        let staged = staged_path(journal, esp, file);
        if staged.try_exists()? {
            let removal = validate_stage(&staged, file)
                .and_then(|()| fs::remove_file(&staged).context("Remove owned staging file"));
            if let Err(error) = removal {
                retained.push(format!("{}: {error:#}", staged.display()));
            }
        }
    }
    let directory = product_dir(esp);
    if !journal.product_directory_existed
        && directory.is_dir()
        && fs::read_dir(&directory)?.next().is_none()
    {
        reject_links(&directory)?;
        fs::remove_dir(&directory)?;
    }
    compare(fw, "BootOrder", Some(&journal.boot_order_before))?;
    ensure!(
        retained.is_empty(),
        "Owned boot entries were removed and the original boot order restored; files with unproven ownership were retained:\n{}",
        retained.join("\n")
    );
    Ok(())
}

fn validate_stage(path: &Path, file: &PlannedFile) -> Result<()> {
    let staged = read_image(path)?;
    if bytes_identity(&staged) == file.identity {
        return Ok(());
    }
    ensure!(
        (staged.len() as u64) < file.identity.bytes,
        "Staging content was replaced"
    );
    let source = read_image(&file.source)
        .context("Partial staging recovery requires the unchanged source image")?;
    ensure!(
        bytes_identity(&source) == file.identity,
        "Source changed; partial staging ownership is unproven"
    );
    ensure!(
        source.starts_with(&staged),
        "Partial staging bytes differ from the original image"
    );
    Ok(())
}

fn remove_owned(path: &Path, expected: &Identity) -> Result<()> {
    if path.try_exists()? {
        reject_links(path)?;
        ensure!(
            identity(path)? == *expected,
            "File ownership changed before removal: {}",
            path.display()
        );
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn save_new(path: &Path, journal: &Journal) -> Result<()> {
    validate(journal)?;
    reject_links(path)?;
    let parent = path
        .parent()
        .context("Journal requires a parent directory")?;
    fs::create_dir_all(parent)?;
    reject_links(parent)?;
    let bytes = serde_json::to_vec_pretty(journal)?;
    ensure!(
        (bytes.len() as u64) < MAX_JOURNAL_SIZE,
        "Installation journal exceeds 1 MiB"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "Create a fresh journal {}; retain previous journals for restore",
                path.display()
            )
        })?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn load(path: &Path) -> Result<Journal> {
    reject_links(path)?;
    let file = fs::File::open(path).with_context(|| format!("Open journal {}", path.display()))?;
    ensure!(
        file.metadata()?.len() <= MAX_JOURNAL_SIZE,
        "Installation journal exceeds 1 MiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_SIZE + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JOURNAL_SIZE,
        "Installation journal exceeds 1 MiB"
    );
    let journal: Journal = serde_json::from_slice(&bytes).context("Parse installation journal")?;
    validate(&journal)?;
    Ok(journal)
}
