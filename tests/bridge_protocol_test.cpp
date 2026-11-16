// Standalone protocol test: include only the transport header, with zero hypercalls or Windows APIs.
#include "../usermode/src/cmd/bridge_protocol.hpp"

#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <sstream>
#include <string>

namespace
{
	namespace bridge = cmd::bridge;

	void require(const bool condition, const char* message)
	{
		if (!condition)
		{
			std::fprintf(stderr, "FAILED: %s\n", message);
			std::exit(1);
		}
	}

	bridge::request parse(const std::string& wire)
	{
		std::istringstream input(wire);
		bridge::line line;
		require(bridge::read_line(input, line) == bridge::read_status::line, "request line read");
		return bridge::parse_request(line);
	}
}

int main()
{
	{
		const auto request = parse("request-A_09\trgvm 0x1234 0x5678 8\n");
		require(request.error == nullptr, "ordinary request accepted");
		require(request.id == "request-A_09", "ID preserved");
		require(request.command == "rgvm 0x1234 0x5678 8", "CLI command preserved");
		require(request.size == request.id.size() + 1 + request.command_size, "received byte sizes");
		std::puts("PASS: ordinary request and sizes");
	}
	{
		const std::string command = "dkm ntoskrnl.exe \"C:\\capture \\exports\"\t--help";
		const auto request = parse("quoted\t" + command + "\r\n");
		require(request.error == nullptr && request.command == command, "quotes, paths, tabs and CRLF preserved");
		std::puts("PASS: command bytes and CRLF");
	}
	{
		const std::string id(bridge::max_id_length, 'a');
		const std::string command(bridge::max_command_length, 'x');
		const auto request = parse(id + "\t" + command + "\r\n");
		require(request.error == nullptr, "exact maximum request accepted");
		require(request.id == id && request.command == command, "maximum bytes preserved");
		require(request.size == bridge::max_request_length, "maximum request size excludes CRLF");
		std::puts("PASS: inclusive ID and command limits");
	}
	{
		const auto request = parse("limit\t" + std::string(bridge::max_command_length + 1, 'x') + "\n");
		require(request.error != nullptr && request.id == "limit", "oversize command retains safe ID");
		require(request.command_size == bridge::max_command_length + 1, "oversize command reports actual size");
		require(request.command.empty(), "oversize command stays undispatched");
		std::puts("PASS: command limit rejection");
	}
	{
		const auto huge_size = bridge::max_command_length * 8;
		std::istringstream input("huge\t" + std::string(huge_size, 'x') + "\r\nnext\thfpc\n");
		bridge::line line;
		require(bridge::read_line(input, line) == bridge::read_status::line, "oversize read");
		require(line.text.size() <= bridge::max_request_length + 1, "bounded retained prefix");
		const auto huge = bridge::parse_request(line);
		require(huge.error != nullptr && huge.command_size == huge_size, "drained line size excludes CRLF");
		require(bridge::read_line(input, line) == bridge::read_status::line, "following read");
		const auto next = bridge::parse_request(line);
		require(next.error == nullptr && next.id == "next" && next.command == "hfpc", "following request aligned");
		require(bridge::read_line(input, line) == bridge::read_status::eof, "EOF after requests");
		std::puts("PASS: bounded draining and stream recovery");
	}
	{
		for (const auto* wire : {"\thfpc\n", "bad id\thfpc\n", "bad:id\thfpc\n", "bad/id\thfpc\n"})
		{
			const auto request = parse(wire);
			require(request.error != nullptr && request.id.empty(), "unsafe ID rejected without correlation");
		}
		const auto request = parse(std::string(bridge::max_id_length + 1, 'a') + "\thfpc\n");
		require(request.error != nullptr && request.id.empty(), "overlong ID rejected");
		std::puts("PASS: malformed and overlong IDs");
	}
	{
		const auto missing = parse("missing-separator\n");
		require(missing.error != nullptr && !missing.has_separator && missing.id.empty(), "missing separator rejected");
		const auto empty = parse("empty\t\r\n");
		require(empty.error != nullptr && empty.id == "empty" && empty.command_size == 0, "empty command rejected with ID");
		const auto blank = parse("\n");
		require(blank.error != nullptr && blank.size == 0, "blank line rejected");
		std::puts("PASS: incomplete and blank request syntax");
	}
	{
		const std::string unicode = "dkm module \"C:\\" "\xc2\xa3\xe4\xb8\xad\xf0\x9f\x98\x80" "\"";
		const auto request = parse("utf8\t" + unicode + "\n");
		require(request.error == nullptr && request.command == unicode, "valid UTF-8 preserved byte-for-byte");
		for (const auto* invalid : {"\x80", "\xc0\x80", "\xe0\x80\x80", "\xed\xa0\x80",
			"\xf0\x80\x80\x80", "\xf4\x90\x80\x80", "\xf8\x88\x80\x80\x80", "\xe2\x82", "\xc2x"})
		{
			const auto rejected = parse(std::string("utf8\tgva ") + invalid + "\n");
			require(rejected.error != nullptr && rejected.id == "utf8", "invalid UTF-8 rejected with ID");
		}
		require(bridge::valid_utf8("\xc2\x80\xe0\xa0\x80\xed\x9f\xbf\xee\x80\x80\xf0\x90\x80\x80\xf4\x8f\xbf\xbf"),
			"valid UTF-8 scalar boundaries");
		std::puts("PASS: UTF-8 validation and preservation");
	}
	{
		const auto nul = parse(std::string("nul\thfpc\0tail\n", 14));
		require(nul.error != nullptr && nul.id == "nul", "embedded NUL rejected");
		const auto cr = parse("cr\thfpc\rtail\n");
		require(cr.error != nullptr && cr.id == "cr", "embedded CR rejected");
		std::puts("PASS: embedded control-byte rejection");
	}
	{
		std::istringstream input("last\texit");
		bridge::line line;
		require(bridge::read_line(input, line) == bridge::read_status::line, "unterminated final line read");
		const auto request = bridge::parse_request(line);
		require(request.error == nullptr && request.command == "exit", "final exit command preserved");
		require(bridge::read_line(input, line) == bridge::read_status::eof, "graceful final EOF");
		std::istringstream empty;
		require(bridge::read_line(empty, line) == bridge::read_status::eof, "immediate EOF");
		std::puts("PASS: EOF and unterminated final request");
	}
	{
		std::istringstream input("request\thfpc\n");
		input.setstate(std::ios::badbit);
		bridge::line line;
		require(bridge::read_line(input, line) == bridge::read_status::error, "I/O errors distinguished from EOF");
		std::puts("PASS: stream error status");
	}
	std::puts("All 11 bridge-protocol test groups passed.");
}
