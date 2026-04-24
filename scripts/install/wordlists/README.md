# Wordlists

## arjun-extended-pt-en.txt

This file is the SamurEye custom parameter wordlist combining Brazilian Portuguese (pt-BR) and English parameter names for use with Arjun during API security assessments.

### Important

- This file is **committed directly into the repository** — it is NOT fetched at runtime.
- Any edits to this file **require a corresponding SHA-256 update** in `../wordlists.json` at key `.wordlists["arjun-extended-pt-en.txt"].sha256`.
- To compute the new SHA-256 after editing:
  ```bash
  sha256sum scripts/install/wordlists/arjun-extended-pt-en.txt
  ```
- The `install.sh` script (via `--install` or `--update`) is responsible for copying this file to:
  ```
  $INSTALL_DIR/wordlists/arjun-extended-pt-en.txt
  ```
- The installed copy is **immutable** — it is reinstalled on every update and is NOT in the preserve-list.

### Editing Policy

Changes to this wordlist require a PR with updated SHA-256 in `wordlists.json`. Use `git blame` to audit changes.
