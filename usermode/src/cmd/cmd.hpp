#pragma once

namespace cmd
{
	void run() noexcept;
	// Called after bridge startup validation; consumes framed requests without an interactive prompt.
	int run_bridge() noexcept;
}
