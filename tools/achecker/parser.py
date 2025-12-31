import re

import sb.parse_utils


VERSION = "2023/02/24"

FINDINGS = {"Violated-AC-Check", "Missing-AC-Check"}

# Patterns for vulnerability detection
PATTERNS = {
    "Violated-AC-Check": re.compile(
        r"^Violated access control check in function\s+(.+)$"
    ),
    "Missing-AC-Check": re.compile(
        r"^Missing access control check in function\s+(.+)$"
    ),
}

# Section headers that indicate end of details
SECTION_HEADERS = (
    "Checking contract for",
    "Violated access control check in function",
    "Missing access control check in function",
)


def parse(
    exit_code: int, log: list[str], output: bytes
) -> tuple[list[dict], set[str], set[str], set[str]]:
    """Parse achecker output for vulnerability findings."""
    findings, infos = [], set()
    errors, fails = sb.parse_utils.errors_fails(
        exit_code, log
    )

    if log is None:
        return findings, infos, errors, fails

    clean_log = list(sb.parse_utils.discard_ansi(log))

    # Check if analysis started
    if not any(
        line.startswith("Checking contract for")
        for line in clean_log
    ):
        if not fails and exit_code != 0:
            infos.add("analysis failed to start")
        return findings, infos, errors, fails

    # Parse findings
    i = 0
    while i < len(clean_log):
        line = clean_log[i]

        # Check all patterns
        for vuln_name, pattern in PATTERNS.items():
            match = pattern.match(line)
            if match:
                finding = {
                    "name": vuln_name,
                    "function": match.group(1).strip(),
                }

                # Collect details from following lines
                details = []
                i += 1
                while i < len(clean_log):
                    next_line = clean_log[i]
                    if any(
                        next_line.startswith(h)
                        for h in SECTION_HEADERS
                    ):
                        break
                    if next_line.strip():
                        details.append(next_line.strip())
                    i += 1

                if details:
                    finding["details"] = "\n".join(details)

                findings.append(finding)
                break
        else:
            i += 1

    # Handle exit code 1
    if exit_code == 1 and not fails:
        errors.discard("EXIT_CODE_1")
        for line in clean_log:
            if "MemoryError" in line:
                errors.add("MemoryError during analysis")
                break
            elif "Error" in line and not line.startswith(
                "Checking"
            ):
                errors.add(line.strip())
                break
        else:
            errors.add("analysis failed with exit code 1")

    return findings, infos, errors, fails
