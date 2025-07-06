# Roo Instructions - test

## rust

## rust

**rust-async-patterns:** Use `async fn` for async functions, prefer `tokio::spawn` for concurrent tasks, use `Arc<Mutex<T>>`
or channels for shared state. Avoid blocking operations in async contexts. Use `select!` for
racing futures, `.await` for sequential operations. Prefer `async-trait` for async trait methods.

**rust-attributes:** Use `#[must_use]` for functions whose return value should be used. Use `#[deprecated]` with
clear migration guidance. Use `#[allow(clippy::...)]` sparingly and with justification.
Use `#[doc = "..."]` for complex documentation that needs formatting, `///` for simple cases.

**rust-avoid-unnecessary-allocation:** Prefer `&str` or `Cow<'_, str>` over `String` when borrowing is sufficient. Avoid `Vec` when arrays
or slices suffice. Optimize for minimal allocation in performance-sensitive or embedded code.

**rust-ci:** Run
- `cargo check`, `cargo fmt`, and `cargo clippy` as part of the CI pipeline to ensure that the code
  follows the correct formatting and style.
- Use `cargo test` to run tests. Ensure that doc tests are also run. Collect coverage information
  using `cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info`.
- Use `cargo mutants` to run mutation tests if configured.
- Use `cargo audit` to check for security vulnerabilities in dependencies.
- Use `cargo deny` to check for license issues in dependencies.

**rust-collections:** Prefer `Vec<T>` for growable arrays, `[T; N]` for fixed-size, `&[T]` for borrowed slices.
Use `HashMap` for key-value lookups, `BTreeMap` when ordering matters, `HashSet`/`BTreeSet`
for unique collections. Consider `IndexMap` when insertion order matters with fast lookups.

**rust-design-api-boundaries:** Minimize the public surface area. Expose only what is necessary using `pub(crate)` or `pub(super)`
where appropriate. Use `#[doc(hidden)]` on internals not meant for public use.

**rust-documentation:** For public items documentation comments are always added. For private items documentation
comments are added when the item is complex or not self-explanatory. Use `///` for simple
documentation comments and `//!` for module-level documentation. Use `#[doc = "..."]` for
complex documentation that needs special formatting. Add examples to documentation comments
when possible, especially for public APIs.

**rust-favour-traits-over-closures:** Use traits for stable interfaces, polymorphism, and when behavior needs to be implemented by external
types. Use closures for short-lived operations, functional transformations, and callbacks. Prefer
`impl Fn()` parameters over trait objects when the closure is the primary interface.

**rust-generics-conventions:** Use conventional generic parameter names: `T` for single type, `K`/`V` for key/value, `E` for error,
`F` for function/closure. Order: lifetime parameters, type parameters, const parameters. Use descriptive
names for domain-specific generics (`TStorage`, `TMessage`). Prefer `impl Trait` over generic parameters
for simple cases.

**rust-logging-conventions:** Use `tracing` for structured logging with `debug!`, `info!`, `warn!`, `error!` macros. Use spans
for request tracing. Include relevant context in log messages. Use `target` parameter for library
code. Prefer structured fields over string interpolation: `info!(user_id = %id, "User logged in")`.

**rust-methods-vs-functions:** Use methods (`&self`, `&mut self`, `self`) when the function operates on the type's data.
Use associated functions (`Self::new()`) for constructors and type-related utilities that don't
need an instance. Use free functions for utilities that work with multiple types or don't
belong to a specific type.

**rust-naming-conventions:** Use `snake_case` for functions, variables, modules; `PascalCase` for types, traits, enums;
`SCREAMING_SNAKE_CASE` for constants. Prefix boolean functions with `is_`, `has_`, `can_`, etc.
Use descriptive names that reveal intent. Avoid abbreviations unless they're domain-standard.

**rust-pattern-matching:** Use `if let` for single pattern matches, `match` for multiple patterns. Prefer exhaustive
matching over catch-all patterns when possible. Use `@` bindings for complex patterns.
Use guards (`if` clauses) sparingly. Order match arms from specific to general. Use `_`
for intentionally ignored values.

**rust-performance:** Profile before optimizing. Use `cargo bench` for microbenchmarks. Prefer `Vec::with_capacity()`
when size is known. Use `&str` over `String` for temporary strings. Consider `Cow<str>` for
conditional ownership. Use `Box<[T]>` instead of `Vec<T>` for fixed-size collections. Profile
allocations with tools like `heaptrack` or `valgrind`.

**rust-string-types:** Use `&str` for string slices, `String` for owned strings, `Cow<str>` when you might need either.
Prefer `&str` in function parameters unless ownership is required. Use `format!()` sparingly in
hot paths - prefer `write!()` to a buffer. Use `Box<str>` for fixed strings that need ownership.

**rust-test-location:** Put unit tests in their own file. They are placed next to the file they
are testing and are named `<file_under_test>_tests.rs`. Reference them from the file under test with
an import, which is placed at the end of the other imports and usings. This pattern separates test logic from
business logic, improving clarity and minimizing rebuild times during development. This will look something like:

``` rust
#[cfg(test)]
#[path = "<file_under_test>_tests.rs"]
mod tests;
```


