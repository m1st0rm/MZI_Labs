def read_file(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    remainder = len(content) % 8
    if remainder != 0:
        content += " " * (8 - remainder)

    return content


def write_file(file_path: str, content: str) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(content)
