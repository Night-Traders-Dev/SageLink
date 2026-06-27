# LinkGuard Journal

## Audit Methodology Patterns
- **Hallucinated Vulnerabilities:** Previous audits contained hallucinated vulnerabilities (e.g. unbounded frame length allocation, replay window unauthenticated state mutation, rekey deadlocks) due to assumptions made without tracing actual code implementation.
- **Evidence-Based Verification:** It is critical to strictly trace execution paths, verify assumptions with codebase evidence (such as grep and precise reading), and never invent theoretical issues. Always prioritize the repository as the sole source of truth.

## Recurring Vulnerabilities & Bottlenecks
- **Memory Exhaustion Pattern:** The `io.readbytes` method was found loading whole files into memory at once for hash verification in `src/app/file.sage`, leading to Out-of-Memory exhaustion when handling large files. This represents a known anti-pattern where whole-file buffering scales poorly on constrained devices. Future code should leverage chunked or streaming alternatives.
- **Path Traversal Edge Case:** Simple sanitization routines (like stripping out `/` and `\`) may inadvertently pass relative paths like `..`. Consider stricter allow-listing of filenames to prevent unintended filesystem interactions.