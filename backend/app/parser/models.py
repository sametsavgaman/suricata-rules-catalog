from pydantic import BaseModel, Field


class RuleOption(BaseModel):
    name: str
    value: str | None = None


class ParsedRule(BaseModel):
    raw_rule: str
    action: str
    protocol: str
    source: str
    source_port: str
    direction: str
    destination: str
    destination_port: str
    sid: int
    rev: int = 1
    msg: str | None = None
    classtype: str | None = None
    metadata: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    flow: list[str] = Field(default_factory=list)
    flowbits: list[str] = Field(default_factory=list)
    contents: list[str] = Field(default_factory=list)
    pcre: list[str] = Field(default_factory=list)
    app_layer: list[dict[str, str | None]] = Field(default_factory=list)
    options: list[RuleOption] = Field(default_factory=list)


class RuleParseError(ValueError):
    pass
