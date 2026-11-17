# hyper-reV loader

Windows x64 boot setup with a [GPUI](<https://gpui.rs/>) window and the same backend through a CLI.

## Setup

1. Keep the four published files together and open `hyperrev-loader.exe`. An unelevated launch requests standard Windows UAC through `ShellExecute` with `runas`.
2. Startup inspects status only. Click **Setup** to find the bundled payloads and ESP, validate, save a recovery journal, and install automatically.
3. Restart manually when ready. **Safe Windows** in the firmware menu starts stock Windows directly, separately from Windows Safe Mode.

The compact window has **Setup**, **Restore**, a status line, and **Advanced**. Its [Liquid Glass-inspired styling](<https://developer.apple.com/documentation/technologyoverviews/liquid-glass>) uses Windows acrylic, translucent capsules, and native draggable/minimize/maximize/close areas. High-contrast mode uses solid surfaces. Restore uses the journal. Advanced reveals **Files**, **ESP**, and **Journal** browse controls, **Defaults**, **Refresh**, **Copy details**, and the raw report. Separate Plan/Apply and reference selection remain CLI options.

Setup creates persistent `Boot####` entries visible in the firmware menu and `bcdedit /enum firmware`:

| Entry | Target |
| --- | --- |
| hyper-reV | `\EFI\hyper-reV\uefi-boot-standalone.efi` |
| Safe Windows | `\EFI\Microsoft\Boot\bootmgfw.efi` |

`BootOrder` becomes `[hyper-reV, Safe Windows, ...original order]`; `BootNext` selects hyper-reV. All original entries remain in their original relative order. The Windows BCD store, Secure Boot policy, services, and Hyper-V settings stay unchanged.

Setup requires Windows already running in UEFI mode, Secure Boot verified off, and Windows Hyper-V binaries present. It checks these preconditions rather than changing them. Payloads must be matching x64 EFI_APPLICATION and DLL images; Windows BOOTAPP images are rejected.

The native stock-Windows helper checks Microsoft signature and version identity. An intact canonical Windows boot manager stays untouched. Only when it is absent may setup restore it from a verified Windows copy or ESP backup; uncertain identities stop setup.

## Build and package

Build the standalone EFI image and architecture-matching attachment first; see the [root build guide](<../README.md#76-standalone-boot-and-debugger-checks>). Install Rust's x64 MSVC toolchain, Visual Studio C++ build tools, and a Windows SDK, then run from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build-loader.ps1 -Publish
```

The published bundle under `%LOCALAPPDATA%\hyper-reV\bin` contains:

```text
hyperrev-loader.exe
hyperrev-setup.exe
uefi-boot-standalone.efi
hyperv-attachment.dll
```

The GUI and CLI discover both payloads beside their executable. Publishing checks SHA-256 identities. Use `-PayloadDirectory C:\path\to\artifacts` to package a different build. The usermode debugger remains separate.

## CLI

Run boot-changing commands from an elevated terminal. Commands print JSON on success and return a nonzero exit code on failure. With the published bundle, `setup` needs zero path arguments:

```powershell
$setup = "$env:LOCALAPPDATA\hyper-reV\bin\hyperrev-setup.exe"
& $setup inspect
& $setup setup
& $setup restore
```

The default recovery journal is `%LOCALAPPDATA%\hyper-reV\boot-install.json`. Keep it for Restore. To use a separate plan and review it before applying:

```powershell
& $setup plan --source C:\hyper-reV\build\Release --journal C:\hyper-reV\boot-install.json
& $setup apply --journal C:\hyper-reV\boot-install.json
& $setup restore --journal C:\hyper-reV\boot-install.json
```

`setup` accepts `--source` for a different payload folder. Use `--esp S:\` with setup, plan, apply, or restore to select an existing ESP mount; otherwise the system ESP is mounted temporarily and released afterward. Setup and plan accept `--reference Boot0000` when Windows-reference selection needs an explicit choice.

## Repeat setup, updates, and Restore

A matching journal, entries, and payload files make repeated **Setup** idempotent: the existing installation stays unchanged. For an update, setup first restores the previous journal-owned installation, archives its journal, then saves and applies a fresh plan. Unknown ownership or conflicting state stops the operation rather than replacing it.

**Restore** cancels the owned next-boot request, restores the recorded original firmware order, and removes both owned entries. It removes only installation-created payloads with matching ownership records; pre-existing matching files remain. Every firmware write is read back. Changed firmware, ESP identity, Windows boot-manager identity, or uncertain file ownership stops the affected operation and appears in the report.

Keep the journal and original source files through setup or recovery. The journal records the recovery plan before changes begin, including for an interrupted installation.

## Development checks

```powershell
cargo fmt --manifest-path loader\Cargo.toml --check
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build-loader.ps1 -Action Clippy
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\build-loader.ps1 -Action Test -Configuration Release
```

Backend tests use temporary fixtures and in-memory firmware. Live development checks are limited to **Inspect** and **Plan**: inspection reads status, and planning saves a journal while leaving ESP boot files and firmware unchanged. Keep boot-changing Setup/Apply/Restore and restarts outside development smoke checks.

The one-click flow follows the [palepale reference](<https://github.com/amangly/palepale>) at commit `6490070271354e2a13a30e107065338c530a7322`, fetched through `gh`. Firmware entries use native UEFI variable APIs rather than parsing localized `bcdedit` output.
