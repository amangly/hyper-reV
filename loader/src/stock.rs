//! Authenticate the stock Windows Boot Manager, optionally restoring an absent
//! canonical file. Existing canonical files are always verified, never replaced.
//! Trust uses Windows' local trust policy/cache, with UI and network retrieval
//! disabled. Version identity comes from the signed image itself, never an MUI.

#[cfg(not(windows))]
use anyhow::Result;
use serde::Serialize;
#[cfg(not(windows))]
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct Report {
    /// The canonical path that passed authentication and image-identity checks.
    pub path: PathBuf,
    /// Present only after a verified source was published to an absent path.
    pub restored_from: Option<PathBuf>,
}

#[cfg(windows)]
pub use native::{prepare, verify};

#[cfg(not(windows))]
pub fn prepare(_esp: &Path, _repair: bool) -> Result<Report> {
    anyhow::bail!("STOCK_PLATFORM_UNSUPPORTED: Windows Boot Manager preparation requires Windows")
}

#[cfg(not(windows))]
pub fn verify(_path: &Path) -> Result<()> {
    anyhow::bail!("STOCK_PLATFORM_UNSUPPORTED: Windows signature verification requires Windows")
}

#[cfg(windows)]
mod native {
    use super::Report;
    use crate::files::{self, Identity};
    use anyhow::{Context, Result, bail, ensure};
    use sha2::{Digest, Sha256};
    use std::ffi::OsString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr::null_mut;
    use uuid::Uuid;
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Cryptography::{
        CERT_NAME_ATTR_TYPE, CertGetNameStringW, szOID_ORGANIZATION_NAME,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
        WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_TYPE_DISK, FileDispositionInfo, GetFileType,
        SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    use windows_sys::core::GUID;

    const MAX_IMAGE_SIZE: u64 = 64 * 1024 * 1024;
    const MAX_PATH_UNITS: usize = 32768;
    const MICROSOFT: &str = "Microsoft Corporation";

    struct Verified {
        bytes: Vec<u8>,
        identity: Identity,
        // A read-only sharing mode excludes writers/deleters throughout copying.
        _file: File,
    }

    fn bytes_identity(bytes: &[u8]) -> Identity {
        Identity {
            bytes: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    fn wide(path: &Path) -> Result<Vec<u16>> {
        let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
        ensure!(
            text.len() < MAX_PATH_UNITS && !text.contains(&0),
            "STOCK_PATH_INVALID: path exceeds the Windows limit or contains NUL: {}",
            path.display()
        );
        text.push(0);
        Ok(text)
    }

    fn open_locked(path: &Path) -> Result<File> {
        files::reject_links(path)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .with_context(|| format!("STOCK_OPEN_FAILED: {}", path.display()))?;
        check_regular(&file, path)?;
        files::reject_links(path)?;
        Ok(file)
    }

    fn check_regular(file: &File, path: &Path) -> Result<()> {
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
            "STOCK_FILE_INVALID: a regular, link-free disk file is required: {}",
            path.display()
        );
        ensure!(
            metadata.len() <= MAX_IMAGE_SIZE,
            "STOCK_IMAGE_TOO_LARGE: the 64 MiB limit was exceeded: {}",
            path.display()
        );
        Ok(())
    }

    fn read_locked(file: &mut File, path: &Path) -> Result<Vec<u8>> {
        files::reject_links(path)?;
        check_regular(file, path)?;
        let expected_length = file.metadata()?.len();
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        (&mut *file)
            .take(MAX_IMAGE_SIZE + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == expected_length && file.metadata()?.len() == expected_length,
            "STOCK_IMAGE_CHANGED: file length changed during reading: {}",
            path.display()
        );
        files::reject_links(path)?;
        Ok(bytes)
    }

    struct TrustState {
        action: GUID,
        data: WINTRUST_DATA,
        open: bool,
    }

    impl TrustState {
        fn close(&mut self) -> Result<()> {
            if !self.open {
                return Ok(());
            }
            self.data.dwStateAction = WTD_STATEACTION_CLOSE;
            let status = unsafe {
                WinVerifyTrust(
                    INVALID_HANDLE_VALUE,
                    &mut self.action,
                    (&mut self.data as *mut WINTRUST_DATA).cast(),
                )
            };
            self.open = false;
            ensure!(
                status == 0,
                "STOCK_TRUST_CLOSE_FAILED: WinVerifyTrust state close returned 0x{:08X}",
                status as u32
            );
            Ok(())
        }
    }

    impl Drop for TrustState {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }

    fn verify_signature(file: &File, path: &Path) -> Result<()> {
        let path_wide = wide(path)?;
        let mut info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path_wide.as_ptr(),
            hFile: file.as_raw_handle(),
            ..Default::default()
        };
        // Both flags are deliberate: chain construction uses cached URLs only,
        // while revocation retrieval/checking is disabled rather than blocking
        // an offline setup. This makes no claim about fresh online revocation.
        let mut state = TrustState {
            action: WINTRUST_ACTION_GENERIC_VERIFY_V2,
            data: WINTRUST_DATA {
                cbStruct: size_of::<WINTRUST_DATA>() as u32,
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_FILE,
                Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
                dwStateAction: WTD_STATEACTION_VERIFY,
                dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
                ..Default::default()
            },
            open: true,
        };
        let status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut state.action,
                (&mut state.data as *mut WINTRUST_DATA).cast(),
            )
        };
        let result = (|| -> Result<()> {
            // WinVerifyTrust returns LONG, not an HRESULT: only zero is success.
            ensure!(
                status == 0,
                "STOCK_SIGNATURE_UNTRUSTED: WinVerifyTrust returned 0x{:08X} for {}",
                status as u32,
                path.display()
            );
            // A signed version label alone is copyable by an unrelated trusted
            // publisher. Also bind the successfully verified leaf certificate
            // to Microsoft's organization, without trusting a display name.
            let provider = unsafe { WTHelperProvDataFromStateData(state.data.hWVTStateData) };
            ensure!(
                !provider.is_null(),
                "STOCK_SIGNER_MISSING: Windows returned empty trust-provider state"
            );
            let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
            ensure!(
                !signer.is_null(),
                "STOCK_SIGNER_MISSING: Windows returned an empty signing chain"
            );
            ensure!(
                unsafe { (*signer).dwError == 0 && (*signer).csCertChain > 0 },
                "STOCK_SIGNER_INVALID: Windows signing-chain status is 0x{:08X}",
                unsafe { (*signer).dwError }
            );
            let certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
            ensure!(
                !certificate.is_null() && unsafe { !(*certificate).pCert.is_null() },
                "STOCK_SIGNER_MISSING: Windows returned an empty signer certificate"
            );
            let certificate = unsafe { (*certificate).pCert };
            let length = unsafe {
                CertGetNameStringW(
                    certificate,
                    CERT_NAME_ATTR_TYPE,
                    0,
                    szOID_ORGANIZATION_NAME.cast(),
                    null_mut(),
                    0,
                )
            };
            ensure!(
                (2..=1024).contains(&length),
                "STOCK_SIGNER_IDENTITY_INVALID: signer organization length {length}; {}",
                io::Error::last_os_error()
            );
            let mut organization = vec![0u16; length as usize];
            let copied = unsafe {
                CertGetNameStringW(
                    certificate,
                    CERT_NAME_ATTR_TYPE,
                    0,
                    szOID_ORGANIZATION_NAME.cast(),
                    organization.as_mut_ptr(),
                    length,
                )
            };
            ensure!(
                copied == length && organization.last() == Some(&0),
                "STOCK_SIGNER_IDENTITY_INVALID: signer organization read failed; {}",
                io::Error::last_os_error()
            );
            let organization = String::from_utf16(&organization[..organization.len() - 1])
                .context("STOCK_SIGNER_IDENTITY_INVALID: organization contains invalid UTF-16")?;
            ensure!(
                organization == MICROSOFT,
                "STOCK_SIGNER_IDENTITY_INVALID: expected Microsoft Corporation, found {organization:?}"
            );
            Ok(())
        })();
        let closing = state.close();
        match (result, closing) {
            (Err(error), Err(close)) => Err(error.context(format!("{close:#}"))),
            (Err(error), _) => Err(error),
            (Ok(()), result) => result,
        }
    }

    fn verified(path: &Path) -> Result<Verified> {
        let mut file = open_locked(path)?;
        let bytes = read_locked(&mut file, path)?;
        files::validate_windows_pe(&bytes)
            .context("STOCK_PE_INVALID: expected an x64 PE32+ EFI/Windows boot application")?;
        let identity = bytes_identity(&bytes);
        ensure!(
            files::identity(path)? == identity,
            "STOCK_IMAGE_CHANGED: path bytes changed before certificate/identity checks: {}",
            path.display()
        );
        file.seek(SeekFrom::Start(0))?;
        let authentication = verify_signature(&file, path).and_then(|()| {
            super::version::verify(&bytes)
                .context("STOCK_VERSION_INVALID: embedded signed Windows Boot Manager identity")
        });
        // Read the locked file AND the path after checking the certificate and
        // embedded identity. Only this authenticated, unchanged snapshot is used.
        ensure!(
            read_locked(&mut file, path)? == bytes && files::identity(path)? == identity,
            "STOCK_IMAGE_CHANGED: bytes changed during certificate/identity checks: {}",
            path.display()
        );
        authentication?;
        Ok(Verified {
            bytes,
            identity,
            _file: file,
        })
    }

    /// Authenticate a link-free, bounded x64 stock Windows Boot Manager.
    pub fn verify(path: &Path) -> Result<()> {
        verified(path)
            .map(|_| ())
            .with_context(|| format!("Verify stock Windows Boot Manager {}", path.display()))
    }

    fn absent(path: &Path) -> Result<bool> {
        files::reject_links(path)?;
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error)
                .with_context(|| format!("STOCK_PATH_INSPECTION_FAILED: {}", path.display())),
        }
    }

    fn windows_source() -> Result<PathBuf> {
        let mut buffer = vec![0u16; MAX_PATH_UNITS];
        let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        ensure!(
            length != 0,
            "STOCK_WINDOWS_DIRECTORY_FAILED: GetWindowsDirectoryW: {}",
            io::Error::last_os_error()
        );
        ensure!(
            (length as usize) < buffer.len() && !buffer[..length as usize].contains(&0),
            "STOCK_WINDOWS_DIRECTORY_INVALID: GetWindowsDirectoryW returned length {length}"
        );
        let directory = PathBuf::from(OsString::from_wide(&buffer[..length as usize]));
        files::reject_links(&directory)?;
        Ok(directory.join("Boot").join("EFI").join("bootmgfw.efi"))
    }

    /// The guard owns only its uniquely created staging path, never the target.
    /// Cleanup checks full expected bytes and deletes through the checked handle
    /// so a name replacement between the check and removal is left untouched.
    struct Stage {
        path: PathBuf,
        expected: Identity,
        owned: bool,
    }

    impl Stage {
        fn create(directory: &Path, expected: Identity) -> Result<(Self, File)> {
            files::reject_links(directory)?;
            let path = directory.join(format!(".hyperrev-stock-{}.stage", Uuid::new_v4()));
            files::reject_links(&path)?;
            let file = OpenOptions::new()
                .write(true)
                .read(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
                .with_context(|| format!("STOCK_STAGE_CREATE_FAILED: {}", path.display()))?;
            Ok((
                Self {
                    path,
                    expected,
                    owned: true,
                },
                file,
            ))
        }

        fn cleanup(&mut self) -> Result<()> {
            if !self.owned {
                return Ok(());
            }
            files::reject_links(&self.path)?;
            // DELETE access plus read-only sharing pins the exact checked file
            // until FileDispositionInfo has marked it for deletion on close.
            let mut file = match OpenOptions::new()
                .access_mode(GENERIC_READ | DELETE)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&self.path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.owned = false;
                    return Ok(());
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "STOCK_STAGE_RETAINED: open owned staging file {}",
                            self.path.display()
                        )
                    });
                }
            };
            let bytes = read_locked(&mut file, &self.path)?;
            ensure!(
                bytes_identity(&bytes) == self.expected,
                "STOCK_STAGE_RETAINED: staging bytes differ or are incomplete: {}",
                self.path.display()
            );
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            let deleted = unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            };
            ensure!(
                deleted != 0,
                "STOCK_STAGE_RETAINED: delete checked staging handle {}: {}",
                self.path.display(),
                io::Error::last_os_error()
            );
            drop(file);
            self.owned = false;
            Ok(())
        }
    }

    impl Drop for Stage {
        fn drop(&mut self) {
            // An explicit cleanup on the error path reports failures. This is
            // also a best-effort fallback during unwinding; mismatches survive.
            let _ = self.cleanup();
        }
    }

    fn publish(source: &Path, checked: &Verified, target: &Path) -> Result<()> {
        ensure!(
            absent(target)?,
            "STOCK_TARGET_APPEARED: canonical target appeared before staging: {}",
            target.display()
        );
        let directory = target
            .parent()
            .context("STOCK_TARGET_INVALID: parent is absent")?;
        files::reject_links(directory)?;
        fs::create_dir_all(directory)
            .with_context(|| format!("STOCK_DIRECTORY_CREATE_FAILED: {}", directory.display()))?;
        files::reject_links(directory)?;
        let (mut stage, mut output) = Stage::create(directory, checked.identity.clone())?;
        let writing = (|| -> Result<()> {
            output
                .write_all(&checked.bytes)
                .context("STOCK_STAGE_WRITE_FAILED: writing authenticated bytes")?;
            output
                .sync_all()
                .context("STOCK_STAGE_SYNC_FAILED: flushing authenticated bytes")?;
            Ok(())
        })();
        drop(output);
        let result = writing.and_then(|()| {
            ensure!(
                files::identity(&stage.path)? == checked.identity,
                "STOCK_STAGE_READBACK_FAILED: SHA-256/length differ for {}",
                stage.path.display()
            );
            ensure!(
                files::identity(source)? == checked.identity,
                "STOCK_SOURCE_CHANGED: source bytes changed before publication: {}",
                source.display()
            );
            ensure!(
                absent(target)?,
                "STOCK_TARGET_APPEARED: canonical target appeared during staging: {}",
                target.display()
            );
            crate::promote::publish_new(&stage.path, target)
                .context("STOCK_PUBLISH_FAILED: atomic create-new publication; existing target preserved")?;
            // Publication consumed our staging name. From here onward cleanup
            // has no authority over either the canonical path or this old name.
            stage.owned = false;
            let installed = verified(target)
                .context("STOCK_INSTALLED_VERIFICATION_FAILED: publication completed; canonical path left untouched")?;
            ensure!(
                installed.identity == checked.identity,
                "STOCK_INSTALLED_READBACK_FAILED: authenticated installed bytes differ from source; canonical path left untouched"
            );
            Ok(())
        });
        match result {
            Ok(()) => Ok(()),
            Err(error) => match stage.cleanup() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(error.context(format!("{cleanup:#}"))),
            },
        }
    }

    /// Verify the existing canonical file. Only an absent target with repair=true
    /// permits recovery, in Windows-source/original/safe priority order.
    pub fn prepare(esp: &Path, repair: bool) -> Result<Report> {
        files::reject_links(esp)?;
        ensure!(
            fs::metadata(esp)
                .with_context(|| format!("STOCK_ESP_INSPECTION_FAILED: {}", esp.display()))?
                .is_dir(),
            "STOCK_ESP_INVALID: an existing ESP directory is required: {}",
            esp.display()
        );
        let target = files::windows_manager(esp);
        if !absent(&target)? {
            verify(&target)
                .context("STOCK_EXISTING_INVALID: existing canonical path was left untouched")?;
            return Ok(Report {
                path: target,
                restored_from: None,
            });
        }
        ensure!(
            repair,
            "STOCK_MISSING (Win32 2): canonical Windows Boot Manager is absent at {}; read-only preparation leaves it unchanged; Full setup is required for stock restoration",
            target.display()
        );
        let directory = target
            .parent()
            .context("STOCK_TARGET_INVALID: parent is absent")?;
        let mut candidates = Vec::new();
        let mut failures = Vec::new();
        match windows_source() {
            Ok(path) => candidates.push(path),
            Err(error) => failures.push(format!("Windows source discovery: {error:#}")),
        }
        candidates.push(directory.join("bootmgfw.original.efi"));
        candidates.push(directory.join("bootmgfw.safe.efi"));
        for source in candidates {
            match verified(&source) {
                Ok(checked) => {
                    publish(&source, &checked, &target)?;
                    return Ok(Report {
                        path: target,
                        restored_from: Some(source),
                    });
                }
                Err(error) => failures.push(format!("{}: {error:#}", source.display())),
            }
        }
        bail!(
            "STOCK_SOURCE_UNAVAILABLE: canonical Windows Boot Manager is absent at {}; every stock source failed verification in priority order:\n{}",
            target.display(),
            failures.join("\n")
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[ignore = "uses the installed Windows source; signature verification is read-only"]
        fn verifies_installed_windows_source_read_only() {
            verify(&windows_source().unwrap()).unwrap();
        }

        #[test]
        fn read_only_missing_target_creates_nothing() {
            let directory = tempfile::tempdir().unwrap();
            let error = prepare(directory.path(), false).unwrap_err();
            assert!(format!("{error:#}").contains("STOCK_MISSING (Win32 2)"));
            assert!(fs::read_dir(directory.path()).unwrap().next().is_none());
        }

        #[test]
        fn invalid_existing_target_is_preserved_even_with_repair() {
            let directory = tempfile::tempdir().unwrap();
            let target = files::windows_manager(directory.path());
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            let original = b"existing canonical bytes owned elsewhere";
            fs::write(&target, original).unwrap();
            let error = prepare(directory.path(), true).unwrap_err();
            assert!(format!("{error:#}").contains("STOCK_EXISTING_INVALID"));
            assert_eq!(fs::read(&target).unwrap(), original);
        }

        #[test]
        fn staging_cleanup_removes_only_full_expected_bytes() {
            let directory = tempfile::tempdir().unwrap();
            let expected = b"authenticated expected image snapshot";
            let (mut stage, mut output) =
                Stage::create(directory.path(), bytes_identity(expected)).unwrap();
            output.write_all(expected).unwrap();
            output.sync_all().unwrap();
            drop(output);
            stage.cleanup().unwrap();
            assert!(!stage.path.exists());
        }

        #[test]
        fn staging_cleanup_retains_changed_or_partial_bytes() {
            let directory = tempfile::tempdir().unwrap();
            let (mut stage, mut output) =
                Stage::create(directory.path(), bytes_identity(b"full expected bytes")).unwrap();
            output.write_all(b"full").unwrap();
            output.sync_all().unwrap();
            drop(output);
            assert!(stage.cleanup().is_err());
            let path = stage.path.clone();
            drop(stage);
            assert_eq!(fs::read(path).unwrap(), b"full");
        }
    }
}

// Parse only the embedded RT_VERSION resource, from the same bytes whose
// Authenticode signature is checked. GetFileVersionInfo can merge MUI strings
// from a different file, which would leave the identity outside that signature.
#[cfg(any(windows, test))]
mod version {
    use anyhow::{Context, Result, ensure};

    const MAX_VERSION_SIZE: usize = 1024 * 1024;

    fn bytes(data: &[u8], start: usize, length: usize) -> Result<&[u8]> {
        let end = start
            .checked_add(length)
            .context("Resource offset overflow")?;
        data.get(start..end)
            .context("Truncated PE/version resource")
    }

    fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(bytes(data, offset, 2)?.try_into()?))
    }

    fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(bytes(data, offset, 4)?.try_into()?))
    }

    fn align4(value: usize) -> Result<usize> {
        Ok(value.checked_add(3).context("Version alignment overflow")? & !3)
    }

    struct Image<'a> {
        data: &'a [u8],
        sections: &'a [u8],
        header_end: usize,
        certificate: Option<(usize, usize)>,
    }

    impl<'a> Image<'a> {
        fn map(&self, rva: u32, length: usize) -> Result<&'a [u8]> {
            let mut mapped = None;
            for section in self.sections.as_chunks::<40>().0 {
                let address = u32_at(section, 12)?;
                let raw_size = u32_at(section, 16)? as usize;
                let raw_start = u32_at(section, 20)? as usize;
                if let Some(relative) = rva.checked_sub(address) {
                    let relative = relative as usize;
                    if relative
                        .checked_add(length)
                        .is_some_and(|end| end <= raw_size)
                    {
                        ensure!(mapped.is_none(), "Overlapping PE resource mappings");
                        ensure!(raw_start >= self.header_end, "Resource overlaps PE headers");
                        bytes(self.data, raw_start, raw_size)?;
                        let start = raw_start
                            .checked_add(relative)
                            .context("Resource mapping overflow")?;
                        let end = start
                            .checked_add(length)
                            .context("Resource length overflow")?;
                        if let Some((certificate_start, certificate_end)) = self.certificate {
                            ensure!(
                                end <= certificate_start || start >= certificate_end,
                                "Version resource overlaps the unsigned certificate table"
                            );
                        }
                        mapped = Some(bytes(self.data, start, length)?);
                    }
                }
            }
            mapped.context("Version resource lacks a bounded raw section mapping")
        }
    }

    fn entries(resource: &[u8], directory: usize) -> Result<Vec<(u32, u32)>> {
        let header = bytes(resource, directory, 16)?;
        let count = u16_at(header, 12)? as usize + u16_at(header, 14)? as usize;
        ensure!(
            count <= 4096,
            "Excessive version-resource directory entries"
        );
        let table = bytes(resource, directory + 16, count * 8)?;
        table
            .as_chunks::<8>()
            .0
            .iter()
            .map(|entry| Ok((u32_at(entry, 0)?, u32_at(entry, 4)?)))
            .collect()
    }

    struct Block<'a> {
        length: usize,
        kind: u16,
        key: String,
        value: &'a [u8],
        children: &'a [u8],
    }

    impl<'a> Block<'a> {
        fn parse(data: &'a [u8]) -> Result<Self> {
            let length = u16_at(data, 0)? as usize;
            ensure!(length >= 8, "Invalid version-block length");
            let data = bytes(data, 0, length)?;
            let value_length = u16_at(data, 2)? as usize;
            let kind = u16_at(data, 4)?;
            ensure!(kind <= 1, "Invalid version-block value type");
            let mut position = 6;
            let mut key = Vec::new();
            loop {
                let unit = u16_at(data, position)?;
                position += 2;
                if unit == 0 {
                    break;
                }
                ensure!(key.len() < 260, "Excessive version-block key length");
                key.push(unit);
            }
            let key = String::from_utf16(&key).context("Invalid UTF-16 version key")?;
            let value_start = align4(position)?.min(length);
            let value_bytes = value_length
                .checked_mul(if kind == 1 { 2 } else { 1 })
                .context("Version value length overflow")?;
            let value = bytes(data, value_start, value_bytes)?;
            let children_start = align4(value_start + value_bytes)?.min(length);
            Ok(Self {
                length,
                kind,
                key,
                value,
                children: &data[children_start..],
            })
        }

        fn text(&self) -> Result<String> {
            ensure!(
                self.kind == 1 && self.value.len() >= 2,
                "Missing version string value"
            );
            let mut units: Vec<u16> = self
                .value
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            ensure!(
                units.pop() == Some(0) && !units.contains(&0),
                "Invalid version string terminator"
            );
            String::from_utf16(&units).context("Invalid UTF-16 version value")
        }
    }

    fn blocks(data: &[u8]) -> Result<Vec<Block<'_>>> {
        let mut output = Vec::new();
        let mut position = 0;
        while position < data.len() {
            if data[position..].iter().all(|byte| *byte == 0) {
                break;
            }
            ensure!(output.len() < 4096, "Excessive version-block children");
            let block = Block::parse(&data[position..])?;
            position = align4(position + block.length)?.min(data.len());
            output.push(block);
        }
        Ok(output)
    }

    fn check_block(data: &[u8]) -> Result<()> {
        let root = Block::parse(data)?;
        ensure!(
            root.key == "VS_VERSION_INFO"
                && root.kind == 0
                && root.value.len() == 52
                && u32_at(root.value, 0)? == 0xFEEF04BD,
            "Expected embedded VS_VERSION_INFO/VS_FIXEDFILEINFO"
        );
        let mut checked = 0;
        for strings in blocks(root.children)? {
            if strings.key != "StringFileInfo" {
                continue;
            }
            ensure!(
                strings.kind == 1 && strings.value.is_empty(),
                "Invalid StringFileInfo block"
            );
            for table in blocks(strings.children)? {
                ensure!(
                    table.kind == 1
                        && table.value.is_empty()
                        && table.key.len() == 8
                        && table.key.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "Invalid version string-table language/codepage"
                );
                let mut original = None;
                let mut company = None;
                let mut product = None;
                for field in blocks(table.children)? {
                    match field.key.as_str() {
                        "OriginalFilename" => {
                            ensure!(
                                original.is_none(),
                                "Duplicate OriginalFilename version field"
                            );
                            original = Some(field.text()?);
                        }
                        "CompanyName" => {
                            ensure!(company.is_none(), "Duplicate CompanyName version field");
                            company = Some(field.text()?);
                        }
                        "ProductName" => {
                            ensure!(product.is_none(), "Duplicate ProductName version field");
                            product = Some(field.text()?);
                        }
                        _ => {}
                    }
                }
                // Current Microsoft bootmgfw.efi legitimately reports the
                // historical internal OriginalFilename=bootmgr.exe. Bind those
                // historical names to Windows product identity as well as the
                // Microsoft signing-certificate organization checked above.
                let manager_name = original.as_deref().is_some_and(|name| {
                    ["bootmgfw.efi", "bootmgfw.exe", "bootmgr.exe"]
                        .iter()
                        .any(|expected| name.eq_ignore_ascii_case(expected))
                });
                let windows_product = product.as_deref().is_some_and(|name| {
                    matches!(
                        name,
                        "Microsoft® Windows® Operating System"
                            | "Microsoft Windows Operating System"
                    )
                });
                ensure!(
                    manager_name
                        && company.as_deref() == Some("Microsoft Corporation")
                        && windows_product,
                    "Expected signed Windows Boot Manager filename, CompanyName=Microsoft Corporation, and Microsoft Windows Operating System product; found {original:?}, {company:?}, {product:?}"
                );
                checked += 1;
            }
        }
        ensure!(checked > 0, "Signed embedded version identity is absent");
        Ok(())
    }

    pub(super) fn verify(data: &[u8]) -> Result<()> {
        crate::files::validate_windows_pe(data)?;
        let pe = u32_at(data, 60)? as usize;
        let optional = pe + 24;
        let optional_size = u16_at(data, pe + 20)? as usize;
        ensure!(
            optional_size >= 136 && u32_at(data, optional + 108)? >= 3,
            "PE resource directory is absent"
        );
        let resource_rva = u32_at(data, optional + 128)?;
        let resource_size = u32_at(data, optional + 132)? as usize;
        ensure!(
            resource_rva != 0 && (16..=64 * 1024 * 1024).contains(&resource_size),
            "Invalid PE resource-directory size"
        );
        let section_count = u16_at(data, pe + 6)? as usize;
        ensure!(
            (1..=96).contains(&section_count),
            "Invalid PE section count"
        );
        let section_start = optional + optional_size;
        let section_size = section_count * 40;
        let sections = bytes(data, section_start, section_size)?;
        let header_end = (u32_at(data, optional + 60)? as usize).max(section_start + section_size);
        let certificate = if optional_size >= 152 && u32_at(data, optional + 108)? >= 5 {
            let start = u32_at(data, optional + 144)? as usize;
            let size = u32_at(data, optional + 148)? as usize;
            if size == 0 {
                None
            } else {
                bytes(data, start, size)?;
                Some((
                    start,
                    start
                        .checked_add(size)
                        .context("Certificate table overflow")?,
                ))
            }
        } else {
            None
        };
        let image = Image {
            data,
            sections,
            header_end,
            certificate,
        };
        let resource = image.map(resource_rva, resource_size)?;
        let mut version_type = None;
        for (name, offset) in entries(resource, 0)? {
            if name == 16 {
                ensure!(
                    version_type.is_none() && offset & 0x80000000 != 0,
                    "Invalid/duplicate RT_VERSION directory"
                );
                version_type = Some((offset & 0x7fffffff) as usize);
            }
        }
        let version_type = version_type.context("Embedded RT_VERSION is absent")?;
        let mut checked = 0;
        for (_, name_offset) in entries(resource, version_type)? {
            ensure!(
                name_offset & 0x80000000 != 0,
                "Invalid version-name directory"
            );
            for (_, language_offset) in entries(resource, (name_offset & 0x7fffffff) as usize)? {
                ensure!(
                    language_offset & 0x80000000 == 0,
                    "Invalid version-language data entry"
                );
                let entry = bytes(resource, language_offset as usize, 16)?;
                let length = u32_at(entry, 4)? as usize;
                ensure!(
                    (8..=MAX_VERSION_SIZE).contains(&length),
                    "Invalid embedded version length"
                );
                check_block(image.map(u32_at(entry, 0)?, length)?)?;
                checked += 1;
                ensure!(checked <= 4096, "Excessive embedded version resources");
            }
        }
        ensure!(checked > 0, "Embedded version resources are empty");
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn put16(data: &mut [u8], at: usize, value: u16) {
            data[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }

        fn put32(data: &mut [u8], at: usize, value: u32) {
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn block(key: &str, kind: u16, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
            let mut data = vec![0u8; 6];
            for unit in key.encode_utf16().chain([0]) {
                data.extend(unit.to_le_bytes());
            }
            while !data.len().is_multiple_of(4) {
                data.push(0);
            }
            data.extend(value);
            for child in children {
                while !data.len().is_multiple_of(4) {
                    data.push(0);
                }
                data.extend(child);
            }
            let length = data.len() as u16;
            put16(&mut data, 0, length);
            put16(
                &mut data,
                2,
                (value.len() / if kind == 1 { 2 } else { 1 }) as u16,
            );
            put16(&mut data, 4, kind);
            data
        }

        fn text(value: &str) -> Vec<u8> {
            value
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect()
        }

        fn version(original: &str, company: &str) -> Vec<u8> {
            let table = block(
                "040904B0",
                1,
                &[],
                &[
                    block("OriginalFilename", 1, &text(original), &[]),
                    block("CompanyName", 1, &text(company), &[]),
                    block(
                        "ProductName",
                        1,
                        &text("Microsoft® Windows® Operating System"),
                        &[],
                    ),
                ],
            );
            let strings = block("StringFileInfo", 1, &[], &[table]);
            let mut fixed = vec![0; 52];
            put32(&mut fixed, 0, 0xFEEF04BD);
            block("VS_VERSION_INFO", 0, &fixed, &[strings])
        }

        fn image(original: &str, company: &str) -> Vec<u8> {
            let version = version(original, company);
            let resource_size = 88 + version.len();
            let raw_size = (resource_size + 511) & !511;
            let mut data = vec![0u8; 0x200 + raw_size];
            data[..2].copy_from_slice(b"MZ");
            put32(&mut data, 60, 0x80);
            data[0x80..0x84].copy_from_slice(b"PE\0\0");
            put16(&mut data, 0x84, 0x8664);
            put16(&mut data, 0x86, 1);
            put16(&mut data, 0x94, 240);
            put16(&mut data, 0x98, 0x20b);
            put32(&mut data, 0x98 + 60, 0x200);
            put16(&mut data, 0x98 + 68, 16);
            put32(&mut data, 0x98 + 108, 16);
            put32(&mut data, 0x98 + 128, 0x1000);
            put32(&mut data, 0x98 + 132, resource_size as u32);
            put32(&mut data, 0x188 + 12, 0x1000);
            put32(&mut data, 0x188 + 16, raw_size as u32);
            put32(&mut data, 0x188 + 20, 0x200);
            let resource = &mut data[0x200..];
            put16(resource, 14, 1);
            put32(resource, 16, 16);
            put32(resource, 20, 0x80000018);
            put16(resource, 24 + 14, 1);
            put32(resource, 40, 1);
            put32(resource, 44, 0x80000030);
            put16(resource, 48 + 14, 1);
            put32(resource, 64, 0x409);
            put32(resource, 68, 72);
            put32(resource, 72, 0x1000 + 88);
            put32(resource, 76, version.len() as u32);
            resource[88..88 + version.len()].copy_from_slice(&version);
            data
        }

        #[test]
        fn accepts_embedded_identity_for_both_windows_subsystems() {
            let mut data = image("bootmgfw.efi", "Microsoft Corporation");
            verify(&data).unwrap();
            put16(&mut data, 0x98 + 68, 10);
            verify(&data).unwrap();
            verify(&image("bootmgr.exe", "Microsoft Corporation")).unwrap();
            verify(&image("bootmgfw.exe", "Microsoft Corporation")).unwrap();
        }

        #[test]
        fn rejects_other_signed_image_identities() {
            assert!(verify(&image("bootmgr.efi", "Microsoft Corporation")).is_err());
            assert!(verify(&image("bootmgfw.efi", "Other Corporation")).is_err());
            assert!(verify(&image("bootmgfw.efi\0other", "Microsoft Corporation")).is_err());
        }

        #[test]
        fn rejects_version_resources_inside_certificate_table() {
            let mut data = image("bootmgfw.efi", "Microsoft Corporation");
            put32(&mut data, 0x98 + 144, 0x200);
            let length = data.len() as u32 - 0x200;
            put32(&mut data, 0x98 + 148, length);
            assert!(verify(&data).is_err());
        }

        #[test]
        fn rejects_resource_cycles_and_truncated_offsets() {
            let mut data = image("bootmgfw.efi", "Microsoft Corporation");
            put32(&mut data, 0x200 + 68, 0x80000000);
            assert!(verify(&data).is_err());
            put32(&mut data, 0x200 + 68, u32::MAX >> 1);
            assert!(verify(&data).is_err());
        }

        #[test]
        fn rejects_missing_identity_and_invalid_machine() {
            let mut data = image("bootmgfw.efi", "Microsoft Corporation");
            put32(&mut data, 0x98 + 128, 0);
            assert!(verify(&data).is_err());
            let mut data = image("bootmgfw.efi", "Microsoft Corporation");
            put16(&mut data, 0x84, 0x14c);
            assert!(verify(&data).is_err());
        }

        #[test]
        fn rejects_all_truncated_fixture_prefixes_without_panicking() {
            let data = image("bootmgfw.efi", "Microsoft Corporation");
            for length in 0..data.len() {
                assert!(verify(&data[..length]).is_err(), "accepted prefix {length}");
            }
        }
    }
}
