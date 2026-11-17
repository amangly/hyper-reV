#[cfg(not(windows))]
use anyhow::Context;
use anyhow::{Result, ensure};
use std::path::Path;

/// Publish a staged payload without replacing a file created by another owner.
pub fn publish_new(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        source.is_absolute() && destination.is_absolute(),
        "Publish paths must be absolute"
    );
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
        let source: Vec<u16> = source.as_os_str().encode_wide().chain([0]).collect();
        let destination: Vec<u16> = destination.as_os_str().encode_wide().chain([0]).collect();
        ensure!(
            !source[..source.len() - 1].contains(&0)
                && !destination[..destination.len() - 1].contains(&0),
            "Publish path contains NUL"
        );
        // Omitting MOVEFILE_REPLACE_EXISTING makes destination creation atomic.
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        ensure!(
            result != 0,
            "Publish staged image without replacement: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    #[cfg(not(windows))]
    {
        // A same-filesystem hard link has create-new semantics on test platforms.
        std::fs::hard_link(source, destination)
            .context("Publish staged image without replacement")?;
        std::fs::remove_file(source).context("Remove the published staging link")?;
        Ok(())
    }
}
