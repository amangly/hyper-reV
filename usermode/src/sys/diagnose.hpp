#pragma once
#include "kernel.hpp"
#include "../nt/kernel_module.hpp"
#include "../util/log.hpp"

#include <array>
#include <cstdint>

namespace sys
{
	// Read-only attachment diagnostics; deliberately skips hook::init().
	inline int diagnose() noexcept
	{
		const auto probe = hc::test();
		LOG_INFO("presence probe: 0x{:x} (expected 0x1337)", probe);
		if (probe != 0x1337)
			return 2;

		kern::curr_cr3 = hc::curr_cr3();
		LOG_INFO("current CR3: 0x{:x}", kern::curr_cr3);
		if (kern::curr_cr3 == 0)
			return 3;

		alignas(4096) std::array<std::uint8_t, 4096> source;
		alignas(4096) std::array<std::uint8_t, 4096> destination;
		source.fill(0xa5);
		destination.fill(0);
		const auto source_va = reinterpret_cast<std::uintptr_t>(source.data());
		const auto destination_va = reinterpret_cast<std::uintptr_t>(destination.data());
		LOG_INFO("self source: VA=0x{:x} GPA=0x{:x}", source_va, hc::translate_va(kern::curr_cr3, source_va));
		LOG_INFO("self destination: VA=0x{:x} GPA=0x{:x}", destination_va, hc::translate_va(kern::curr_cr3, destination_va));
		const bool copied = hc::virt_copy(kern::curr_cr3, source_va, kern::curr_cr3, destination_va, source.size());
		const bool matched = copied && source == destination;
		LOG_INFO("self virtual-copy: returned={} bytes_match={}", copied, matched);

		const nt::kernel_modules modules;
		LOG_INFO("native kernel-module query: usable={} count={}", static_cast<bool>(modules), modules.count());
		bool kernel_header_ok = false;
		std::size_t index = 0;
		for (const auto module : modules)
		{
			if (index++ == 3)
				break;
			destination.fill(0);
			const auto gpa = hc::translate_va(kern::curr_cr3, module.base);
			const bool read = kern::read(module.base, std::span<std::uint8_t>(destination));
			const bool mz = destination[0] == 'M' && destination[1] == 'Z';
			LOG_INFO("module '{}': VA=0x{:x} size=0x{:x} GPA=0x{:x} header_read={} bytes={:02x} {:02x} MZ={}",
				module.name, module.base, module.size, gpa, read, destination[0], destination[1], mz);
			if (module.name == "ntoskrnl.exe")
				kernel_header_ok = read && mz;
		}

		if (!matched || !kernel_header_ok)
			return 4;

		if (!kern::init())
			return 4;
		const auto kernel = kern::nt();
		LOG_INFO("debugger module cache: {} modules; ntoskrnl.exe exports={}",
			kern::modules_list.size(), kernel->second.exports.size());
		return kernel->second.exports.empty() ? 4 : 0;
	}
}
