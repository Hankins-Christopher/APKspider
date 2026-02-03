import re
from typing import Iterable

PATH_RE = re.compile(r"(/[^\s]+)")


def sanitize_log_line(line: str) -> str:
    sanitized = PATH_RE.sub("[path]", line)
    return sanitized.replace("\x00", "")


def sanitize_log_lines(lines: Iterable[str]) -> str:
    return "".join(sanitize_log_line(line) for line in lines)
