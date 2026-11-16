#include "priv.hpp"
#include "../util/log.hpp"

#include <Windows.h>

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG privilege, BOOLEAN enable, BOOLEAN current_thread,
                                             PBOOLEAN previous_enabled);

nt::privilege::privilege(const std::uint32_t priv) noexcept
	: priv_(priv)
{
	BOOLEAN prev = 0;

	const auto status = RtlAdjustPrivilege(priv_, TRUE, FALSE, &prev);
	if (status >= 0)
	{
		prev_state_ = prev;
		acquired_ = true;
	}
	else
	{
		LOG_ERR("RtlAdjustPrivilege({}) failed: NTSTATUS=0x{:08x}", priv_, static_cast<std::uint32_t>(status));
	}
}

nt::privilege::~privilege() noexcept
{
	if (!acquired_)
		return;

	BOOLEAN discard = 0;
	RtlAdjustPrivilege(priv_, prev_state_, FALSE, &discard);
}
