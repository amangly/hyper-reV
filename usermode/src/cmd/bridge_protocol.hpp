#pragma once

#include <cstddef>
#include <cstdint>
#include <istream>
#include <limits>
#include <string>
#include <string_view>

// Transport-only helpers: this header has zero debugger or platform dependencies.
namespace cmd::bridge
{
	inline constexpr std::size_t max_id_length = 64;
	inline constexpr std::size_t max_command_length = 16384; // UTF-8 bytes, excluding the line ending.
	inline constexpr std::size_t max_request_length = max_id_length + 1 + max_command_length;
	inline constexpr int invalid_request_status = 64;

	struct line
	{
		std::string text;
		std::size_t size = 0; // Full received byte count, excluding LF and an optional preceding CR.
	};

	enum class read_status { line, eof, error };

	// Drain oversized lines while retaining a bounded prefix, so the next request stays aligned.
	inline read_status read_line(std::istream& input, line& output)
	{
		output.text.clear();
		output.size = 0;
		bool received = false;
		char last = 0;
		char ch;

		while (input.get(ch))
		{
			received = true;
			if (ch == '\n')
				break;

			last = ch;
			if (output.size != (std::numeric_limits<std::size_t>::max)())
				++output.size;
			// One extra byte permits a maximum-sized request terminated by CRLF.
			if (output.text.size() < max_request_length + 1)
				output.text.push_back(ch);
		}

		if (input.bad() || (input.fail() && !input.eof()))
			return read_status::error;
		if (!received)
			return read_status::eof;

		if (last == '\r' && output.size != (std::numeric_limits<std::size_t>::max)())
		{
			--output.size;
			if (output.text.size() > output.size)
				output.text.resize(output.size);
		}
		return read_status::line;
	}

	inline bool valid_id(const std::string_view id) noexcept
	{
		if (id.empty() || id.size() > max_id_length)
			return false;
		for (const auto ch : id)
		{
			if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '-'))
				return false;
		}
		return true;
	}

	inline bool valid_utf8(const std::string_view text) noexcept
	{
		for (std::size_t i = 0; i < text.size();)
		{
			const auto first = static_cast<unsigned char>(text[i++]);
			if (first <= 0x7f)
				continue;

			std::size_t remaining;
			std::uint32_t value;
			std::uint32_t minimum;
			if ((first & 0xe0) == 0xc0)
			{
				remaining = 1;
				value = first & 0x1f;
				minimum = 0x80;
			}
			else if ((first & 0xf0) == 0xe0)
			{
				remaining = 2;
				value = first & 0x0f;
				minimum = 0x800;
			}
			else if ((first & 0xf8) == 0xf0)
			{
				remaining = 3;
				value = first & 0x07;
				minimum = 0x10000;
			}
			else
				return false;

			if (text.size() - i < remaining)
				return false;
			for (std::size_t n = 0; n < remaining; ++n)
			{
				const auto next = static_cast<unsigned char>(text[i++]);
				if ((next & 0xc0) != 0x80)
					return false;
				value = (value << 6) | (next & 0x3f);
			}
			if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
				return false;
		}
		return true;
	}

	struct request
	{
		std::string id; // Populated only for a valid, safely frameable ID.
		std::string command;
		std::size_t size = 0;
		std::size_t command_size = 0;
		bool has_separator = false;
		const char* error = nullptr;
	};

	inline request parse_request(const line& input)
	{
		request output;
		output.size = input.size;
		const auto separator = input.text.find('\t');
		if (separator == std::string::npos)
		{
			output.error = "expected <id> TAB <commandline>";
			return output;
		}
		output.has_separator = true;
		output.command_size = input.size - separator - 1;

		const auto id = std::string_view(input.text).substr(0, separator);
		if (!valid_id(id))
		{
			output.error = "id must match [A-Za-z0-9_-]{1,64}";
			return output;
		}
		output.id.assign(id);

		if (output.command_size > max_command_length)
			output.error = "command exceeds byte limit";
		else if (output.command_size == 0)
			output.error = "command is empty";
		else
		{
			const auto command = std::string_view(input.text).substr(separator + 1);
			if (!valid_utf8(command))
				output.error = "command is invalid UTF-8";
			else if (command.find('\0') != std::string_view::npos || command.find('\r') != std::string_view::npos)
				output.error = "command contains NUL or embedded CR";
			else
				output.command.assign(command);
		}
		return output;
	}
}
