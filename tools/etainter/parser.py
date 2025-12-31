import re

import sb.parse_utils


VERSION = "2023/02/24"

FINDINGS = {"Unbounded loop", "DoS with failed call"}

# Patterns for vulnerability detection and detail extraction
PATTERNS = {
    "Unbounded loop": {
        "main": re.compile(
            r"^Unbounded loop condition in function:\s*(.+)$"
        ),
        "detail": re.compile(
            r"^Following loop bound is tainted in function\s+(.+)$"
        ),
        "message_template": "Loop bound is tainted in function {}",
    },
    "DoS with failed call": {
        "main": re.compile(
            r"^DoS-With-Failed-Call in function:\s*(.+)$"
        ),
        "detail": re.compile(
            r"^Following call target is tainted in function\s+(.+)$"
        ),
        "message_template": "Call target is tainted in function {}",
    },
}


def parse(
    exit_code: int, log: list[str], output: bytes
) -> tuple[list[dict], set[str], set[str], set[str]]:
    """Parse etainter output for vulnerability findings."""
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
        for vuln_name, patterns in PATTERNS.items():
            match = patterns["main"].match(line)
            if match:
                finding = {
                    "name": vuln_name,
                    "function": match.group(1).strip(),
                }

                # Check for additional details in next lines
                if i + 1 < len(clean_log):
                    next_line = clean_log[i + 1]
                    detail_match = patterns["detail"].match(
                        next_line
                    )
                    if detail_match:
                        finding["message"] = patterns[
                            "message_template"
                        ].format(
                            detail_match.group(1).strip()
                        )
                        i += 1

                        # Check for instruction details
                        if i + 1 < len(clean_log):
                            inst_line = clean_log[i + 1]
                            if (
                                inst_line.strip()
                                and not inst_line.startswith(
                                    "Checking"
                                )
                            ):
                                finding["details"] = (
                                    inst_line.strip()
                                )
                                i += 1

                findings.append(finding)
                break

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
