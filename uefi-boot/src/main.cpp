#include "mem/mem.hpp"
#include "bootmgfw/bootmgfw.hpp"
#include "efi/boot.hpp"
#include "efi/status.hpp"
#include "hyperv_attachment/hva.hpp"

extern "C" {
#include <visual-uefi/EDK-II/BaseLib/vshacks.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
}

extern "C" CONST UINT8 _gDriverUnloadImageCount = 1;
extern "C" CONST UINT32 _gUefiDriverRevision = 0x200;
extern "C" CHAR8* gEfiCallerBaseName = "hyper-reV";

extern "C"
EFI_STATUS
EFIAPI
UefiUnload (
    IN EFI_HANDLE ImageHandle
    )
{
    (void)ImageHandle;
    return EFI_SUCCESS;
}

extern "C"
EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable
    )
{
#if defined(HYPERREV_STANDALONE_BOOT)
    Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: standalone firmware launch\r\n"));
#endif

    Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: locating boot volume\r\n"));
    efi::status stat = efi::find_boot_info();

    if (!stat)
    {
        Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: boot volume failed: %r (0x%lx)\r\n"), stat.value(), stat.value());
        return stat.value();
    }

    Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: initializing memory\r\n"));
    stat = mem::init();

    if (!stat)
    {
        Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: memory initialization failed: %r (0x%lx)\r\n"), stat.value(), stat.value());
        return stat.value();
    }

    Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: reading attachment\r\n"));
    stat = hva::load_from_disk();

    if (!stat)
    {
        Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: attachment load failed: %r (0x%lx)\r\n"), stat.value(), stat.value());
        return stat.value();
    }

    Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: starting Windows boot manager\r\n"));
#if defined(HYPERREV_STANDALONE_BOOT)
    stat = bootmgfw::start_hooked();
#else
    stat = bootmgfw::restore_and_start_hooked();
#endif
    Print(reinterpret_cast<const CHAR16*>(L"hyper-reV: Windows boot manager returned: %r (0x%lx)\r\n"), stat.value(), stat.value());
    return stat.value();
}
