"""Snort fields are attacker-influenced (rule messages, file names, even protocol strings). Clean them before storing."""
import unicodedata

# Control characters (Cc) and invisible formatting characters (Cf), which include the bidirectional overrides used
# in "Trojan Source" style spoofing and zero-width characters used to disguise look-alike strings.
_STRIP = {"Cc", "Cf"}
_SPACE_LIKE = {"\t", "\n", "\r", "\x0b", "\x0c"}


def clean_text(value: str, max_length: int) -> str:
    out = []
    for ch in value:
        if ch in _SPACE_LIKE:
            out.append(" ")
        elif unicodedata.category(ch) in _STRIP:
            continue
        else:
            out.append(ch)
    return " ".join("".join(out).split())[:max_length]


def safe_filename(value: str, max_length: int = 255) -> str:
    """Basename only. A name supplied by the network never gets to describe a path."""
    name = value.replace("\\", "/").rsplit("/", 1)[-1]
    name = clean_text(name, max_length)
    return "" if name in {".", ".."} else name
