# These hacks are required for the test binaries depending on the dynamic library libstd-*.so
# See: https://github.com/rust-lang/cargo/issues/4651
#
# We also need to exclude the derive macro from coverage because it will always show as 0% by
# virtue of executing at compile-time outside the view of Tarpaulin.
#
# The trybuild `compile_fail` test is skipped (and its harness excluded from the report): it
# builds its test cases in a child cargo/rustc process which Tarpaulin cannot instrument (and
# which exceeds its response timeout), yielding no coverage.
coverage:
	env LD_LIBRARY_PATH="$(shell rustc --print sysroot)/lib" \
	cargo-tarpaulin --workspace --all-features --out xml --exclude tree_hash_derive \
		--exclude-files tree_hash/tests/trybuild.rs \
		-- --skip compile_fail

.PHONY: coverage
