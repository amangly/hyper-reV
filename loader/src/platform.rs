//! Native boot-setup boundaries. This module never edits BCD or Windows policy.

use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct MachineInfo {
    /// Membership in the Administrators group for the current effective token.
    pub administrator: bool,
    pub firmware: String,
    /// The UEFI SecureBoot byte; unavailable or malformed values produce None.
    pub secure_boot: Option<bool>,
    /// Presence of hvix64.exe or hvax64.exe in the Windows system directory only.
    /// This says nothing about CPU support, signatures, configuration, or activity.
    pub hyperv_available: bool,
}

#[cfg(windows)]
mod native {
    use super::MachineInfo;
    use crate::boot::{Firmware, Variable};
    use anyhow::{Context, Result, bail, ensure};
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io;
    use std::marker::PhantomData;
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::process::CommandExt;
    use std::path::{Component, Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::rc::Rc;
    use uuid::Uuid;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ENVVAR_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA,
        ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, SetLastError, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        SE_SYSTEM_ENVIRONMENT_NAME, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenImpersonation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetLogicalDrives,
        GetVolumeNameForVolumeMountPointW, GetVolumePathNameW, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        IOCTL_DISK_GET_PARTITION_INFO_EX, PARTITION_INFORMATION_EX, PARTITION_STYLE_GPT,
    };
    use windows_sys::Win32::System::SystemInformation::{
        FirmwareTypeBios, FirmwareTypeUefi, GetFirmwareType, GetSystemDirectoryW,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateMutexW, GetCurrentProcess, GetCurrentThread, OpenProcessToken,
        OpenThreadToken, ReleaseMutex, SetThreadToken, WaitForSingleObject,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        GetFirmwareEnvironmentVariableExW, SetFirmwareEnvironmentVariableExW,
    };
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};

    pub fn elevate_gui_if_needed() -> Result<bool> {
        if unsafe { IsUserAnAdmin() } != 0 {
            return Ok(false);
        }
        let executable = std::env::current_exe().context("Locate the setup executable")?;
        let executable = wide(executable.as_os_str())?;
        let verb = wide(OsStr::new("runas"))?;
        let result = unsafe {
            ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                executable.as_ptr(),
                null(),
                null(),
                1,
            )
        } as isize;
        ensure!(
            result > 32,
            "Windows elevation did not start the setup window (ShellExecute result {result})"
        );
        Ok(true)
    }

    const NAMESPACE: &str = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
    const MUTEX_NAME: &str = r"Global\hyper-reV-firmware-boot";
    const MAX_VARIABLE_BYTES: usize = 1024 * 1024;
    const MAX_PATH_UNITS: usize = 32768;
    const ESP_TYPE: Uuid = Uuid::from_u128(0xc12a7328_f81f_11d2_ba4b_00a0c93ec93b);

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn win32_error(operation: &str, code: u32) -> anyhow::Error {
        anyhow::Error::new(io::Error::from_raw_os_error(code as i32)).context(operation.to_owned())
    }

    fn last_error(operation: &str) -> anyhow::Error {
        win32_error(operation, unsafe { GetLastError() })
    }

    fn wide(value: &OsStr) -> Result<Vec<u16>> {
        let mut encoded: Vec<_> = value.encode_wide().collect();
        ensure!(
            !encoded.contains(&0),
            "Win32 argument contains an embedded NUL"
        );
        ensure!(
            encoded.len() < MAX_PATH_UNITS,
            "Win32 argument exceeds the path-length limit"
        );
        encoded.push(0);
        Ok(encoded)
    }

    fn path_from_buffer(buffer: &[u16]) -> Result<PathBuf> {
        let length = buffer
            .iter()
            .position(|unit| *unit == 0)
            .context("Unterminated Win32 path")?;
        ensure!(length != 0, "Win32 returned an empty volume path");
        Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
    }

    // Only the duplicate is adjusted. The process token and other threads retain
    // their privileges, including during a background preflight probe.
    struct EnvironmentPrivilege {
        token: Handle,
        previous_state: TOKEN_PRIVILEGES,
        previous_thread: Option<Handle>,
        installed: bool,
        _thread_bound: PhantomData<Rc<()>>,
    }

    impl EnvironmentPrivilege {
        fn enable() -> Result<Self> {
            let mut original = null_mut();
            let previous_thread = if unsafe {
                OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                    1,
                    &mut original,
                )
            } != 0
            {
                Some(Handle(original))
            } else {
                let error = unsafe { GetLastError() };
                ensure!(
                    error == ERROR_NO_TOKEN,
                    "{}",
                    win32_error("OpenThreadToken", error)
                );
                None
            };
            let process_token = if previous_thread.is_none() {
                let mut token = null_mut();
                if unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_QUERY | TOKEN_DUPLICATE,
                        &mut token,
                    )
                } == 0
                {
                    return Err(last_error("OpenProcessToken"));
                }
                Some(Handle(token))
            } else {
                None
            };
            let source = previous_thread
                .as_ref()
                .or(process_token.as_ref())
                .context("Missing source token")?;
            let mut duplicate = null_mut();
            if unsafe {
                DuplicateTokenEx(
                    source.0,
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES,
                    null(),
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut duplicate,
                )
            } == 0
            {
                return Err(last_error("DuplicateTokenEx"));
            }
            let mut guard = Self {
                token: Handle(duplicate),
                previous_state: TOKEN_PRIVILEGES::default(),
                previous_thread,
                installed: false,
                _thread_bound: PhantomData,
            };
            let mut desired = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                ..TOKEN_PRIVILEGES::default()
            };
            desired.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if unsafe {
                LookupPrivilegeValueW(
                    null(),
                    SE_SYSTEM_ENVIRONMENT_NAME,
                    &mut desired.Privileges[0].Luid,
                )
            } == 0
            {
                return Err(last_error(
                    "LookupPrivilegeValueW(SeSystemEnvironmentPrivilege)",
                ));
            }
            let mut returned = 0;
            unsafe { SetLastError(ERROR_SUCCESS) };
            let adjusted = unsafe {
                AdjustTokenPrivileges(
                    guard.token.0,
                    0,
                    &desired,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    &mut guard.previous_state,
                    &mut returned,
                )
            };
            let error = unsafe { GetLastError() };
            if adjusted == 0 || error != ERROR_SUCCESS {
                let operation = if error == ERROR_NOT_ALL_ASSIGNED {
                    "SeSystemEnvironmentPrivilege is absent from the effective token"
                } else {
                    "AdjustTokenPrivileges(SeSystemEnvironmentPrivilege)"
                };
                return Err(win32_error(operation, error));
            }
            if unsafe { SetThreadToken(null(), guard.token.0) } == 0 {
                return Err(last_error("SetThreadToken"));
            }
            guard.installed = true;
            Ok(guard)
        }
    }

    impl Drop for EnvironmentPrivilege {
        fn drop(&mut self) {
            unsafe {
                if self.installed {
                    let original = self
                        .previous_thread
                        .as_ref()
                        .map_or(null_mut(), |token| token.0);
                    SetThreadToken(null(), original);
                }
                if self.previous_state.PrivilegeCount != 0 {
                    AdjustTokenPrivileges(
                        self.token.0,
                        0,
                        &self.previous_state,
                        0,
                        null_mut(),
                        null_mut(),
                    );
                }
            }
        }
    }

    /// Acquire, use, and drop on one thread; the privilege is thread-local.
    pub struct NativeFirmware {
        _privilege: EnvironmentPrivilege,
    }

    impl NativeFirmware {
        pub fn open() -> Result<Self> {
            Ok(Self {
                _privilege: EnvironmentPrivilege::enable()?,
            })
        }
    }

    fn read_variable(name: &str) -> Result<Option<Variable>> {
        let name_wide = wide(OsStr::new(name))?;
        let namespace = wide(OsStr::new(NAMESPACE))?;
        let mut capacity = 1024;
        loop {
            let mut data = vec![0u8; capacity];
            let mut attributes = 0;
            unsafe { SetLastError(ERROR_SUCCESS) };
            let length = unsafe {
                GetFirmwareEnvironmentVariableExW(
                    name_wide.as_ptr(),
                    namespace.as_ptr(),
                    data.as_mut_ptr().cast(),
                    data.len() as u32,
                    &mut attributes,
                )
            } as usize;
            if length != 0 {
                ensure!(
                    length <= data.len(),
                    "Firmware returned an oversized variable length"
                );
                data.truncate(length);
                return Ok(Some(Variable { attributes, data }));
            }
            let error = unsafe { GetLastError() };
            if error == ERROR_ENVVAR_NOT_FOUND {
                return Ok(None);
            }
            if matches!(error, ERROR_INSUFFICIENT_BUFFER | ERROR_MORE_DATA) {
                ensure!(
                    capacity < MAX_VARIABLE_BYTES,
                    "Firmware variable {name} exceeds the 1 MiB limit"
                );
                capacity = (capacity * 2).min(MAX_VARIABLE_BYTES);
                continue;
            }
            ensure!(
                error != ERROR_SUCCESS,
                "Firmware variable {name} returned zero bytes without an error"
            );
            return Err(win32_error(
                &format!("GetFirmwareEnvironmentVariableExW({name})"),
                error,
            ));
        }
    }

    fn writable_variable(name: &str) -> bool {
        matches!(name, "BootNext" | "BootOrder")
            || (name.len() == 8
                && name.starts_with("Boot")
                && name.as_bytes()[4..]
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F')))
    }

    impl Firmware for NativeFirmware {
        fn get(&self, name: &str) -> Result<Option<Variable>> {
            read_variable(name)
        }

        fn put(&mut self, name: &str, value: Option<&Variable>) -> Result<()> {
            ensure!(
                writable_variable(name),
                "Writes are restricted to BootNext, BootOrder, and individual uppercase Boot#### variables"
            );
            let name_wide = wide(OsStr::new(name))?;
            let namespace = wide(OsStr::new(NAMESPACE))?;
            let (data, attributes) = value.map_or((&[][..], 0), |variable| {
                (variable.data.as_slice(), variable.attributes)
            });
            ensure!(
                data.len() <= MAX_VARIABLE_BYTES,
                "Firmware variable exceeds the 1 MiB limit"
            );
            let pointer = if data.is_empty() {
                null()
            } else {
                data.as_ptr().cast()
            };
            if unsafe {
                SetFirmwareEnvironmentVariableExW(
                    name_wide.as_ptr(),
                    namespace.as_ptr(),
                    pointer,
                    data.len() as u32,
                    attributes,
                )
            } == 0
            {
                return Err(last_error(&format!(
                    "SetFirmwareEnvironmentVariableExW({name})"
                )));
            }
            Ok(())
        }
    }

    /// The same non-waiting named mutex used by tools/firmware_boot.py.
    pub struct MutationLock {
        handle: Handle,
        _thread_bound: PhantomData<Rc<()>>,
    }

    impl MutationLock {
        pub fn acquire() -> Result<Self> {
            let name = wide(OsStr::new(MUTEX_NAME))?;
            let raw = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
            ensure!(
                !raw.is_null(),
                "{}",
                last_error("CreateMutexW(firmware boot)")
            );
            let handle = Handle(raw);
            match unsafe { WaitForSingleObject(handle.0, 0) } {
                WAIT_OBJECT_0 => Ok(Self {
                    handle,
                    _thread_bound: PhantomData,
                }),
                WAIT_ABANDONED => {
                    // An abandoned wait grants ownership. Release it even though
                    // this operation stops and requires inspection of the journal.
                    unsafe { ReleaseMutex(handle.0) };
                    bail!(
                        "Previous firmware operation was interrupted; inspect firmware and the saved journal first"
                    )
                }
                WAIT_TIMEOUT => bail!("Another firmware-boot operation holds the mutation lock"),
                WAIT_FAILED => Err(last_error("WaitForSingleObject(firmware boot)")),
                result => bail!("Unexpected firmware mutex wait result {result:#x}"),
            }
        }
    }

    impl Drop for MutationLock {
        fn drop(&mut self) {
            unsafe { ReleaseMutex(self.handle.0) };
        }
    }

    fn resolved_path(path: &Path) -> Result<PathBuf> {
        ensure!(path.is_absolute(), "Volume paths require an absolute path");
        ensure!(
            !path
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
            "Volume paths contain parent traversal"
        );
        wide(path.as_os_str())?;
        let mut ancestor = path.to_path_buf();
        let mut missing = Vec::new();
        loop {
            match fs::symlink_metadata(&ancestor) {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let name = ancestor
                        .file_name()
                        .context("Path has no existing volume ancestor")?
                        .to_os_string();
                    missing.push(name);
                    ensure!(ancestor.pop(), "Path has no existing volume ancestor");
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("Inspect {}", ancestor.display()));
                }
            }
        }
        // mountvol /S can expose a drive without a DOS-normalized final path.
        // Resolve components lexically and reject links; volume identity is
        // established separately through the GPT IOCTL rather than a drive alias.
        let mut resolved: PathBuf = ancestor.components().collect();
        crate::files::reject_links(&resolved)?;
        ensure!(
            missing.is_empty() || resolved.is_dir(),
            "Existing path ancestor is a file"
        );
        for name in missing.into_iter().rev() {
            resolved.push(name);
        }
        Ok(resolved)
    }

    fn volume_root(path: &Path) -> Result<PathBuf> {
        let encoded = wide(path.as_os_str())?;
        let mut buffer = vec![0u16; MAX_PATH_UNITS];
        if unsafe { GetVolumePathNameW(encoded.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) }
            == 0
        {
            return Err(last_error("GetVolumePathNameW"));
        }
        path_from_buffer(&buffer)
    }

    fn volume_name(root: &Path) -> Result<PathBuf> {
        let encoded = wide(root.as_os_str())?;
        let mut buffer = vec![0u16; MAX_PATH_UNITS];
        if unsafe {
            GetVolumeNameForVolumeMountPointW(
                encoded.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        } == 0
        {
            return Err(last_error("GetVolumeNameForVolumeMountPointW"));
        }
        path_from_buffer(&buffer)
    }

    fn guid_uuid(guid: windows_sys::core::GUID) -> Uuid {
        Uuid::from_fields(guid.data1, guid.data2, guid.data3, &guid.data4)
    }

    /// The actual GPT partition GUID, after checking its EFI system-partition type.
    pub fn partition_id(path: &Path) -> Result<String> {
        let resolved = resolved_path(path)?;
        let volume = volume_name(&volume_root(&resolved)?)?;
        let mut device: Vec<_> = volume.as_os_str().encode_wide().collect();
        ensure!(
            device.last() == Some(&u16::from(b'\\')),
            "Volume device path lacks its trailing separator"
        );
        device.pop();
        device.push(0);
        let raw = unsafe {
            CreateFileW(
                device.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        ensure!(
            raw != INVALID_HANDLE_VALUE && !raw.is_null(),
            "{}",
            last_error("CreateFileW(volume)")
        );
        let handle = Handle(raw);
        let mut information = PARTITION_INFORMATION_EX::default();
        let mut returned = 0;
        if unsafe {
            DeviceIoControl(
                handle.0,
                IOCTL_DISK_GET_PARTITION_INFO_EX,
                null(),
                0,
                (&mut information as *mut PARTITION_INFORMATION_EX).cast(),
                size_of::<PARTITION_INFORMATION_EX>() as u32,
                &mut returned,
                null_mut(),
            )
        } == 0
        {
            return Err(last_error("IOCTL_DISK_GET_PARTITION_INFO_EX"));
        }
        ensure!(
            returned as usize >= size_of::<PARTITION_INFORMATION_EX>(),
            "Truncated GPT partition information"
        );
        ensure!(
            information.PartitionStyle == PARTITION_STYLE_GPT,
            "Selected path resides outside a GPT partition"
        );
        let gpt = unsafe { information.Anonymous.Gpt };
        ensure!(
            guid_uuid(gpt.PartitionType) == ESP_TYPE,
            "Selected path resides outside an EFI system partition"
        );
        let identity = guid_uuid(gpt.PartitionId);
        ensure!(
            !identity.is_nil(),
            "EFI system partition has an empty GPT partition GUID"
        );
        Ok(identity.to_string())
    }

    fn equal_component(left: &OsStr, right: &OsStr) -> bool {
        fn fold(unit: u16) -> u16 {
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&unit) {
                unit + 32
            } else {
                unit
            }
        }
        left.encode_wide()
            .map(fold)
            .eq(right.encode_wide().map(fold))
    }

    /// Reject reparse points in existing ancestors, including before creation of
    /// EFI\hyper-reV. The core enforces the exact dedicated relative directory.
    pub fn volume_relative_path(path: &Path) -> Result<String> {
        let resolved = resolved_path(path)?;
        let root = resolved_path(&volume_root(&resolved)?)?;
        let mut components = resolved.components();
        for expected in root.components() {
            let actual = components
                .next()
                .context("Resolved path is shorter than its volume root")?;
            ensure!(
                equal_component(actual.as_os_str(), expected.as_os_str()),
                "Resolved path differs from its actual volume root"
            );
        }
        let mut relative = Vec::new();
        for component in components {
            match component {
                Component::Normal(name) => relative.push(
                    name.to_str()
                        .context("UEFI path contains invalid Unicode")?
                        .to_owned(),
                ),
                _ => bail!("Unexpected component in the volume-relative path"),
            }
        }
        Ok(format!(r"\{}", relative.join(r"\")))
    }

    fn system_directory() -> Result<PathBuf> {
        let mut capacity = 260;
        loop {
            let mut buffer = vec![0u16; capacity];
            let length =
                unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
            ensure!(length != 0, "{}", last_error("GetSystemDirectoryW"));
            if length < buffer.len() {
                return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
            }
            ensure!(
                length < MAX_PATH_UNITS,
                "Windows system directory exceeds the path-length limit"
            );
            capacity = length + 1;
        }
    }

    fn run_mountvol(executable: &Path, drive: &str, action: &str) -> Result<()> {
        let output = Command::new(executable)
            .args([drive, action])
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .with_context(|| format!("Run {} {drive} {action}", executable.display()))?;
        ensure!(
            output.status.success(),
            "mountvol {drive} {action} exited with {}: {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    struct OwnedEspMount {
        executable: PathBuf,
        drive: String,
        root: PathBuf,
        volume: Option<PathBuf>,
    }

    impl Drop for OwnedEspMount {
        fn drop(&mut self) {
            let still_owned = match &self.volume {
                Some(expected) => volume_name(&self.root).is_ok_and(|current| {
                    equal_component(current.as_os_str(), expected.as_os_str())
                }),
                // This is only the immediate unwind after a successful /S whose
                // volume-name query failed, before the mount is exposed to callers.
                None => true,
            };
            if still_owned {
                let _ = run_mountvol(&self.executable, &self.drive, "/D");
            }
        }
    }

    pub struct EspMount {
        root: PathBuf,
        _owned: Option<OwnedEspMount>,
    }

    fn validated_esp_root(path: &Path) -> Result<PathBuf> {
        ensure!(
            path.is_absolute(),
            "An explicit ESP root requires an absolute directory path"
        );
        let selected =
            resolved_path(path).with_context(|| format!("Resolve ESP root {}", path.display()))?;
        ensure!(
            selected.is_dir(),
            "Selected ESP root requires an existing directory"
        );
        let root = resolved_path(&volume_root(&selected)?)?;
        ensure!(
            equal_component(selected.as_os_str(), root.as_os_str()),
            "Selected ESP directory differs from its volume root"
        );
        partition_id(&root)?;
        ensure!(
            root.join(r"EFI\Microsoft\Boot").is_dir(),
            "Selected ESP lacks the Microsoft boot directory"
        );
        Ok(root)
    }

    impl EspMount {
        pub fn open(requested: Option<&Path>) -> Result<Self> {
            if let Some(path) = requested {
                return Ok(Self {
                    root: validated_esp_root(path)?,
                    _owned: None,
                });
            }
            let executable = system_directory()?.join("mountvol.exe");
            ensure!(
                executable.is_file(),
                "Windows system mountvol.exe is missing"
            );
            let mask = unsafe { GetLogicalDrives() };
            ensure!(mask != 0, "{}", last_error("GetLogicalDrives"));
            let letter = (b'D'..=b'Z')
                .rev()
                .find(|letter| mask & (1u32 << (*letter - b'A')) == 0)
                .context("An unused drive letter is required to mount the Windows ESP")?;
            let drive = format!("{}:", char::from(letter));
            run_mountvol(&executable, &drive, "/S")?;
            let root = PathBuf::from(format!("{drive}\\"));
            let mut owner = OwnedEspMount {
                executable,
                drive,
                root: root.clone(),
                volume: None,
            };
            owner.volume = Some(volume_name(&root)?);
            Ok(Self {
                root: validated_esp_root(&root)?,
                _owned: Some(owner),
            })
        }

        pub fn root(&self) -> &Path {
            &self.root
        }
    }

    fn secure_boot_state() -> Option<bool> {
        let variable = match read_variable("SecureBoot") {
            Ok(value) => value,
            Err(_) => NativeFirmware::open().ok()?.get("SecureBoot").ok()?,
        }?;
        match variable.data.as_slice() {
            [0] => Some(false),
            [1] => Some(true),
            _ => None,
        }
    }

    pub fn machine_info() -> MachineInfo {
        let administrator = unsafe { IsUserAnAdmin() } != 0;
        let mut kind = 0;
        let firmware = if unsafe { GetFirmwareType(&mut kind) } == 0 {
            format!("Unknown ({})", last_error("GetFirmwareType"))
        } else if kind == FirmwareTypeUefi {
            "UEFI".to_owned()
        } else if kind == FirmwareTypeBios {
            "BIOS".to_owned()
        } else {
            format!("Unknown ({kind})")
        };
        let secure_boot = if kind == FirmwareTypeUefi {
            secure_boot_state()
        } else {
            None
        };
        let hyperv_available = system_directory().is_ok_and(|directory| {
            directory.join("hvix64.exe").is_file() || directory.join("hvax64.exe").is_file()
        });
        MachineInfo {
            administrator,
            firmware,
            secure_boot,
            hyperv_available,
        }
    }
}

#[cfg(not(windows))]
mod native {
    use super::MachineInfo;
    use crate::boot::{Firmware, Variable};
    use anyhow::{Result, bail};
    use std::path::{Path, PathBuf};

    pub struct NativeFirmware;

    impl NativeFirmware {
        pub fn open() -> Result<Self> {
            bail!("Native firmware access requires Windows")
        }
    }

    impl Firmware for NativeFirmware {
        fn get(&self, _name: &str) -> Result<Option<Variable>> {
            bail!("Native firmware access requires Windows")
        }

        fn put(&mut self, _name: &str, _value: Option<&Variable>) -> Result<()> {
            bail!("Native firmware access requires Windows")
        }
    }

    pub struct MutationLock;

    impl MutationLock {
        pub fn acquire() -> Result<Self> {
            bail!("The firmware mutation lock requires Windows")
        }
    }

    pub struct EspMount {
        root: PathBuf,
    }

    impl EspMount {
        pub fn open(_requested: Option<&Path>) -> Result<Self> {
            bail!("Native ESP access requires Windows")
        }

        pub fn root(&self) -> &Path {
            &self.root
        }
    }

    pub fn elevate_gui_if_needed() -> Result<bool> {
        Ok(false)
    }

    pub fn partition_id(_path: &Path) -> Result<String> {
        bail!("Native ESP partition identity requires Windows")
    }

    pub fn volume_relative_path(_path: &Path) -> Result<String> {
        bail!("Native volume-relative paths require Windows")
    }

    pub fn machine_info() -> MachineInfo {
        MachineInfo {
            administrator: false,
            firmware: "Requires Windows".to_owned(),
            secure_boot: None,
            hyperv_available: false,
        }
    }
}

pub use native::{
    EspMount, MutationLock, NativeFirmware, elevate_gui_if_needed, machine_info, partition_id,
    volume_relative_path,
};
