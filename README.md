# Linux Dropper (Educational)

**Disclaimer:**
This project is for educational and authorized security lab use only.
Do **not** use on systems without explicit permission!
The author is not responsible for any misuse.

---

## Overview

This project is a simple Linux dropper utility written in C.
It demonstrates secure file handling, basic obfuscation, process execution, and logging—intended for security research, C learning, and portfolio use.

---

## Features

* Reads a user-supplied executable file from disk
* Applies simple XOR obfuscation and de-obfuscation (for demonstration)
* Saves the file to a randomized path in `/tmp`
* Executes the dropped file and waits for its completion
* Logs all actions and errors to `/tmp/downloader.log`
* Optionally deletes the dropped file after execution (`--cleanup`)
* Optionally self-deletes the dropper itself after running (`--self-remove`)

---

## Usage

```bash
gcc dropper.c -o dropper
./dropper <input_file> [--cleanup] [--self-remove]
```

**Example:**

```bash
./dropper ./hello --cleanup
```

**Options:**

* `--cleanup` : Remove dropped file after execution.
* `--self-remove` : Dropper deletes itself after running (be careful).

---

## How It Works

1. Reads the given executable file into memory.
2. Obfuscates the file content using XOR.
3. De-obfuscates it (for demonstration).
4. Saves to a random filename in `/tmp`.
5. Executes the dropped file.
6. Cleans up and logs every step.

---

## Legal Notice

**This program is provided for educational and authorized testing purposes only.
Do NOT use on systems you do not own or do not have permission to test.
The author assumes no liability for misuse.**

---

## License

This project is licensed under the MIT License.
See the LICENSE file for details.

---

## About

Made by Said in 2025 for cybersecurity learning and portfolio.
Questions or suggestions? \[[said.mammadov.linkedin@gmail.com](mailto:your@email.com)]

---
