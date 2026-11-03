# ADR-004: Strict Deterministic Binary Execution over LLM-Generated Dynamic Shell Scripts

## Status
Accepted

## Context
Many experimental offensive AI frameworks allow the LLM to generate raw shell commands (e.g. `curl ...`, `nmap ...`, `python -c ...`) which are passed directly to `subprocess.Popen(cmd, shell=True)` or `os.system()`.

In an autonomous penetration testing platform, this pattern introduces unacceptable vulnerabilities:
1. **Command Injection via Malicious Target Content:** If a target web application returns malicious output, it can manipulate the LLM via indirect prompt injection to execute arbitrary commands (`rm -rf /`, exfiltrating local keys).
2. **Uncontrolled Fuzzing & Out-of-Scope Destruction:** The LLM might generate destructive commands or bypass rate limits.
3. **Flaky Parsing:** LLMs frequently produce syntax errors in bash commands.

## Decision
We enforce an absolute architectural ban on LLM shell generation:
$$\text{Dynamic Shell Execution from LLM Strings} \equiv \emptyset$$

All security testing tools (`nuclei`, `katana`, `ffuf`, `httpx`, `subfinder`) must be executed via deterministic Python wrapper classes inheriting from `BaseToolRunner`. Tools are spawned using `asyncio.create_subprocess_exec` with strongly-typed argument arrays (`argv: List[str]`), non-root execution, timeout monitors, and validated Pydantic parameter schemas.

## Consequences & Trade-offs
### Positive:
- Total immunity to command injection vulnerabilities.
- Guaranteed rate limit enforcement and target scope validation prior to process spawning.
- Structured, predictable output parsing via JSONL streams.

### Negative:
- The system cannot run arbitrary ad-hoc command-line utilities that have not been wrapped in a formal tool runner class.
- Adding a new tool integration requires implementing a Python wrapper and Pydantic schema.

