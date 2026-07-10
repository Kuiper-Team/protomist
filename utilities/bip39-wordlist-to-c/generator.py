from pathlib import Path

wordlists_directory = Path.cwd() / "trezor"
c_path = (Path.cwd() / ".." / ".." / "source" / "wordlists" / "languages.h").resolve()

template = """#ifndef languages_h
#define languages_h

#include "../constants.h"

{body}

#endif
"""

generated = ""

for filename in wordlists_directory.glob("*.txt"):
    generated += f"\nconst char* { filename.stem }_list[bip39_wordlist_size] {{\n"

    dummy = ""
    with open(filename, "r") as wordlist_file:
        for line in wordlist_file:
            dummy += "    \"" + line.strip() + "\",\n"
    dummy = dummy.rstrip(",\n") + "\n" #Remove the last comma

    generated += dummy
    generated += "\n};\n"

generated = template.format(body=generated)
with open(c_path, "w", encoding="utf-8") as c_file:
    c_file.write(generated)
