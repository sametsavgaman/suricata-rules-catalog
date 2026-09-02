from app.parser.models import RuleOption, RuleParseError


def split_unquoted(text: str, delimiter: str) -> list[str]:
    """Split on a delimiter only when outside quotes; retain escaped characters."""
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            current.append(char)
            remainder = text[index + 1 :].lstrip()
            if char == quote and (not remainder or remainder.startswith(delimiter)):
                quote = None
            continue
        if char == '"':
            quote = char
            current.append(char)
        elif char == delimiter:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quote:
        raise RuleParseError("Unterminated quoted string in rule options")
    if current or text.endswith(delimiter):
        parts.append("".join(current).strip())
    return parts


def split_option(raw: str) -> RuleOption:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(raw):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char == '"':
            quote = char
        elif char == ":":
            return RuleOption(name=raw[:index].strip().lower(), value=raw[index + 1 :].strip())
    return RuleOption(name=raw.strip().lower(), value=None)


def parse_options(text: str) -> list[RuleOption]:
    return [split_option(part) for part in split_unquoted(text, ";") if part]


def unquote(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def comma_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in split_unquoted(value, ",") if item.strip()]
