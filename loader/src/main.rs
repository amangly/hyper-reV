#![cfg_attr(windows, windows_subsystem = "windows")]

fn run() -> anyhow::Result<()> {
    if hyperrev_loader::platform::elevate_gui_if_needed()? {
        return Ok(());
    }
    hyperrev_loader::ui::run()
}

fn main() {
    if let Err(error) = run() {
        let message = format!("hyper-reV loader: {error:#}");
        eprintln!("{message}");
        #[cfg(windows)]
        {
            use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
            let text: Vec<_> = message.encode_utf16().chain([0]).collect();
            let title: Vec<_> = "hyper-reV Setup".encode_utf16().chain([0]).collect();
            unsafe {
                MessageBoxW(
                    std::ptr::null_mut(),
                    text.as_ptr(),
                    title.as_ptr(),
                    MB_OK | MB_ICONERROR,
                );
            }
        }
        std::process::exit(1);
    }
}
