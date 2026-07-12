from pathlib import Path

wordlists_directory = Path.cwd() / "trezor"
c_path = (Path.cwd() / ".." / ".." / "source" / "wordlists" / "languages.c").resolve()
h_path = (Path.cwd() / ".." / ".." / "source" / "wordlists" / "languages.h").resolve()

c_template = """#include "languages.h"

#include "../constants.h"
{body}
#endif
"""
h_template = """#ifndef languages_h
#define languages_h

#include "../constants.h"
{body}

#endif
"""

c_generated = ""
h_generated = ""

for filename in wordlists_directory.glob("*.txt"):
    c_generated += f"\nconst char* { filename.stem }_list[bip39_wordlist_size] {{\n"

    dummy = ""
    with open(filename, "r") as wordlist_file:
        for line in wordlist_file:
            dummy += "    \"" + line.strip() + "\",\n"
    dummy = dummy.rstrip(",\n") + "\n" #Remove the last comma

    c_generated += dummy
    c_generated += "\n};\n"

    h_generated += f"\nconst char* { filename.stem }_list[bip39_wordlist_size];"

c_generated = c_template.format(body=c_generated)
with open(c_path, "w", encoding="utf-8") as c_file:
    c_file.write(c_generated)

h_generated = h_template.format(body=h_generated)
with open(h_path, "w", encoding="utf-8") as h_file:
    h_file.write(h_generated)
