// Exercises the actual query wrapper with a deterministic NT API replacement.
// This executable performs zero hypercalls and never queries kernel modules.
#define NOMINMAX
#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "../usermode/src/nt/query.hpp"

namespace
{
	struct reply
	{
		std::uint32_t status;
		ULONG required;
		ULONG expected_capacity;
	};

	std::vector<reply> replies;
	std::size_t call = 0;

	void require(const bool condition, const char* message)
	{
		if (!condition)
		{
			std::fprintf(stderr, "FAILED: %s\n", message);
			std::exit(1);
		}
	}

	void run(const char* name, std::vector<reply> sequence, const std::size_t expected_bytes)
	{
		replies = std::move(sequence);
		call = 0;
		const auto result = nt::query_system_info(11);
		require(result.size() == expected_bytes, "result length");
		require(call == replies.size(), "API call count");
		for (const auto value : result)
			require(value == 0x5a, "returned bytes");
		std::printf("PASS: %s\n", name);
	}
}

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(ULONG info_class, PVOID output,
                                                   ULONG capacity, PULONG required)
{
	require(info_class == 11, "information class");
	require(call < replies.size(), "unexpected API call");
	const auto response = replies[call++];
	require(capacity == response.expected_capacity, "allocated capacity");
	require((capacity == 0) == (output == nullptr), "buffer/probe arguments");
	*required = response.required;
	const auto status = static_cast<NTSTATUS>(response.status);
	if (status >= 0 && output)
	{
		const auto count = response.required < capacity ? response.required : capacity;
		for (ULONG i = 0; i < count; ++i)
			static_cast<std::uint8_t*>(output)[i] = 0x5a;
	}
	return status;
}

int main()
{
	constexpr std::uint32_t mismatch = 0xc0000004;
	run("ordinary probe and fill", {{mismatch, 16, 0}, {0, 16, 16}}, 16);
	run("module list grows between calls", {{mismatch, 8, 0}, {mismatch, 32, 8}, {0, 32, 32}}, 32);
	run("growth without returned size", {{mismatch, 8, 0}, {mismatch, 0, 8}, {0, 16, 16}}, 16);
	run("access denial stops immediately", {{0xc0000022, 0, 0}}, 0);
	run("allocation cap", {{mismatch, 64 * 1024 * 1024 + 1, 0}}, 0);
	run("invalid successful returned length", {{mismatch, 8, 0}, {0, 16, 8}}, 0);
	run("non-resize error stops immediately", {{mismatch, 8, 0}, {0xc0000001, 0, 8}}, 0);
	run("bounded retry exhaustion", {{mismatch, 8, 0}, {mismatch, 16, 8}, {mismatch, 32, 16},
		{mismatch, 64, 32}, {mismatch, 128, 64}, {mismatch, 256, 128}, {mismatch, 512, 256}}, 0);
	std::puts("All 8 query-wrapper tests passed.");
}
