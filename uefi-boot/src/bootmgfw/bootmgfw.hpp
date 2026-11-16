#pragma once
#include "../efi/status.hpp"

namespace bootmgfw
{
	// Standalone launch leaves the Windows boot-manager file untouched.
	efi::status start_hooked();
	efi::status restore_and_start_hooked();
}
