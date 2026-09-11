from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LoadResult:
    rules: list[str] = field(default_factory=list)
    ignored_lines: int = 0


class RuleLoader:
    def load_file(self, path: Path) -> LoadResult:
        return self.load_text(path.read_text(encoding="utf-8", errors="replace"))

    def load_text(self, text: str) -> LoadResult:
        result = LoadResult()
        current: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if not current and (not stripped or stripped.startswith("#")):
                result.ignored_lines += 1
                continue
            current.append(stripped)
            # Suricata option values (notably reference:url) may contain
            # unquoted parentheses. The rule delimiter is the terminal ')'.
            if "(" in " ".join(current) and stripped.endswith(")"):
                candidate = " ".join(current).strip()
                if candidate:
                    result.rules.append(candidate)
                current = []
        if current:
            raise ValueError("Incomplete multiline rule at end of input")
        return result
