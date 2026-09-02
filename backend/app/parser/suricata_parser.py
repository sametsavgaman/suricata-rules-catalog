from app.parser.models import ParsedRule, RuleParseError
from app.parser.option_parser import comma_values, parse_options, unquote


APP_LAYER_OPTIONS = {
    "app-layer-protocol",
    "dns.query",
    "dns.opcode",
    "dns.rrtype",
    "file_data",
    "file.name",
    "http.uri",
    "http.uri.raw",
    "http.method",
    "http.host",
    "http.host.raw",
    "http.header",
    "http.header.raw",
    "http.user_agent",
    "http.request_body",
    "http.response_body",
    "http.stat_code",
    "http.stat_msg",
    "tls.sni",
    "tls.cert_subject",
    "tls.cert_issuer",
    "ssh.software",
    "smtp.helo",
}


def _find_option_bounds(rule: str) -> tuple[int, int]:
    quote: str | None = None
    escaped = False
    bracket_depth = 0
    start = -1
    for index, char in enumerate(rule):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char == '"':
            quote = char
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif char == "(" and bracket_depth == 0:
            start = index
            break
    if start < 0:
        raise RuleParseError("Rule has no option block")

    end = len(rule.rstrip()) - 1
    if end <= start or rule[end] != ")":
        raise RuleParseError("Unterminated option block")
    return start, end


def _tokenize_header(header: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    bracket_depth = 0
    quote: str | None = None
    escaped = False
    for char in header.strip():
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif quote:
            current.append(char)
            if char == quote:
                quote = None
        elif char == '"':
            quote = char
            current.append(char)
        elif char == "[":
            bracket_depth += 1
            current.append(char)
        elif char == "]":
            bracket_depth -= 1
            current.append(char)
        elif char.isspace() and bracket_depth == 0:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        tokens.append("".join(current))
    if bracket_depth != 0 or quote:
        raise RuleParseError("Malformed rule header")
    return tokens


class SuricataRuleParser:
    def parse(self, raw_rule: str) -> ParsedRule:
        normalized = " ".join(line.strip() for line in raw_rule.strip().splitlines())
        start, end = _find_option_bounds(normalized)
        header_tokens = _tokenize_header(normalized[:start])
        if len(header_tokens) != 7:
            raise RuleParseError(f"Expected 7 header fields, got {len(header_tokens)}")
        action, protocol, source, source_port, direction, destination, destination_port = header_tokens
        if direction not in {"->", "<>", "<-"}:
            raise RuleParseError(f"Unsupported direction: {direction}")

        options = parse_options(normalized[start + 1 : end])
        by_name: dict[str, list[str | None]] = {}
        for option in options:
            by_name.setdefault(option.name, []).append(option.value)

        def first(name: str) -> str | None:
            values = by_name.get(name, [])
            return values[0] if values else None

        try:
            sid = int(first("sid") or "")
            rev = int(first("rev") or "1")
        except ValueError as exc:
            raise RuleParseError("sid and rev must be integers") from exc

        app_layer = [
            {"name": option.name, "value": unquote(option.value)}
            for option in options
            if option.name in APP_LAYER_OPTIONS or option.name.startswith(("http.", "dns.", "tls.", "ssh.", "smtp."))
        ]
        return ParsedRule(
            raw_rule=normalized,
            action=action,
            protocol=protocol,
            source=source,
            source_port=source_port,
            direction=direction,
            destination=destination,
            destination_port=destination_port,
            sid=sid,
            rev=rev,
            msg=unquote(first("msg")),
            classtype=first("classtype"),
            metadata=[value for raw in by_name.get("metadata", []) for value in comma_values(raw)],
            references=[unquote(value) or "" for value in by_name.get("reference", [])],
            flow=[value for raw in by_name.get("flow", []) for value in comma_values(raw)],
            flowbits=[unquote(value) or "" for value in by_name.get("flowbits", [])],
            contents=[unquote(value) or "" for value in by_name.get("content", [])],
            pcre=[unquote(value) or "" for value in by_name.get("pcre", [])],
            app_layer=app_layer,
            options=options,
        )
