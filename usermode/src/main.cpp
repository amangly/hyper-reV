#include "cmd/cmd.hpp"
#include "sys/sys.hpp"
#include "sys/diagnose.hpp"
#include "util/log.hpp"
#include "hypercall/hypercall.hpp"

#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <string_view>

int main(const int argc, char* argv[])
{
	if (argc == 2 && std::string_view{ argv[1] } == "--bridge")
	{
		std::setvbuf(stdout, nullptr, _IONBF, 0);
		std::setvbuf(stderr, nullptr, _IONBF, 0);
		// Keep UTF-8 input untouched and emit exact LF protocol delimiters on Windows.
		if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
			_setmode(_fileno(stdout), _O_BINARY) == -1 ||
			_setmode(_fileno(stderr), _O_BINARY) == -1)
		{
			LOG_ERR("bridge startup: failed to configure binary stdio");
			return 1;
		}

		const auto response = hc::test();
		if (response != 0x1337)
		{
			LOG_ERR("bridge startup: hyper-reV probe returned 0x{:x} (expected 0x1337)", response);
			return 2;
		}
		// Bridge startup intentionally leaves the hook arena untouched until an akh request.
		if (!sys::kern::init())
		{
			LOG_ERR("bridge startup: kernel initialization failed");
			return 4;
		}

		std::fputs("@hyperrev:ready:1\n", stdout);
		std::fflush(stdout);
		return cmd::run_bridge();
	}

	if (argc == 2 && std::string_view{ argv[1] } == "--diagnose")
		return sys::diagnose();

	if (argc == 2 && std::string_view{ argv[1] } == "--check")
	{
		const auto response = hc::test();
		LOG_INFO("hyper-reV probe: 0x{:x} (expected 0x1337)", response);

		if (response != 0x1337)
		{
			LOG_ERR("hyper-reV attachment did not respond to the presence probe");
			return 2;
		}

		const auto cr3 = hc::curr_cr3();
		LOG_INFO("guest CR3: 0x{:x}", cr3);

		if (cr3 == 0)
		{
			LOG_ERR("hyper-reV presence probe passed, but the CR3 query returned zero");
			return 3;
		}

		LOG_INFO("hyper-reV attachment is loaded and responding");
		return 0;
	}

	if (argc == 2 && std::string_view{ argv[1] } == "--modules")
	{
		if (!sys::kern::init())
			return 4;
		for (const auto& [name, info] : sys::kern::modules_list)
			LOG_INFO("'{}' base=0x{:X} size=0x{:X}", name, info.base, info.size);
		LOG_INFO("kernel-module count: {}", sys::kern::modules_list.size());
		return 0;
	}

	if (argc > 1)
	{
		LOG_INFO("Usage: usermode.exe [--check|--diagnose|--modules|--bridge]");
		return 64;
	}

	if (!sys::init())
	{
		LOG_ERR("sys::init failed");
		return 1;
	}

	cmd::run();
	return 0;
}
