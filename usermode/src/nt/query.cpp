#include "query.hpp"
#include "../util/log.hpp"

#define NOMINMAX
#include <Windows.h>

#include <algorithm>

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(ULONG info_class, PVOID info_out, ULONG info_size,
                                                   PULONG returned_size);

namespace
{
	constexpr std::uint32_t status_access_denied = 0xc0000022;
	constexpr std::uint32_t status_info_length_mismatch = 0xc0000004;
	constexpr std::uint32_t status_buffer_too_small = 0xc0000023;
	constexpr ULONG maximum_query_bytes = 64 * 1024 * 1024;

	void report_query_failure(const std::uint32_t info_class, const NTSTATUS status,
	                          const ULONG size) noexcept
	{
		LOG_ERR("NtQuerySystemInformation({}) failed: NTSTATUS=0x{:08x} required_bytes={}",
			info_class, static_cast<std::uint32_t>(status), size);

		if (info_class != nt::system_module_information_class ||
			static_cast<std::uint32_t>(status) != status_access_denied)
			return;

		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
			return;

		DWORD returned = 0;
		GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &returned);
		if (returned > 0)
		{
			std::vector<std::uint8_t> buffer(returned);
			if (GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), returned, &returned))
			{
				const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
				const auto count = *GetSidSubAuthorityCount(label->Label.Sid);
				if (count > 0)
				{
					const auto rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
					LOG_ERR("kernel-module query: process integrity RID=0x{:x}", rid);
					if (rid < SECURITY_MANDATORY_MEDIUM_RID)
						LOG_ERR("Low Integrity blocks kernel-module enumeration even with administrator privileges. Launch the deployed debugger from %LOCALAPPDATA%\\hyper-reV\\bin.");
				}
			}
		}
		CloseHandle(token);
	}
}

std::vector<std::uint8_t> nt::query_system_info(const std::uint32_t info_class) noexcept
{
	ULONG size = 0;
	const auto probe_status = NtQuerySystemInformation(info_class, nullptr, 0, &size);
	if (size == 0 || size > maximum_query_bytes)
	{
		report_query_failure(info_class, probe_status, size);
		return {};
	}

	// A driver may load between the size probe and fill; retry bounded growth.
	for (unsigned attempt = 0; attempt < 6; ++attempt)
	{
		std::vector<std::uint8_t> buffer(size);
		ULONG required = 0;
		const auto status = NtQuerySystemInformation(info_class, buffer.data(), size, &required);
		if (status >= 0)
		{
			if (required > buffer.size())
			{
				LOG_ERR("NtQuerySystemInformation({}) returned an invalid output length", info_class);
				return {};
			}
			if (required > 0)
				buffer.resize(required);
			return buffer;
		}

		const auto code = static_cast<std::uint32_t>(status);
		if (code != status_info_length_mismatch && code != status_buffer_too_small)
		{
			report_query_failure(info_class, status, required);
			return {};
		}

		const auto next_size = std::max<std::uint64_t>(required, static_cast<std::uint64_t>(size) * 2);
		if (next_size > maximum_query_bytes)
		{
			report_query_failure(info_class, status, required);
			return {};
		}
		size = static_cast<ULONG>(next_size);
	}

	LOG_ERR("NtQuerySystemInformation({}) kept changing size across six attempts", info_class);
	return {};
}
