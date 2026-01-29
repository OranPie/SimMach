from __future__ import annotations


def norm_path(path: str) -> str:
    if not path:
        return "/"
    if not path.startswith("/"):
        raise ValueError("path must be absolute")
    parts: list[str] = []
    for part in path.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)
