

# ELF Security Scanner (User-Mode)

This program is a **user‑mode ELF scanner for Linux** that inspects a binary’s sections and reports potential indicators of embedded or obfuscated code.  

- Validates the ELF64 header  
- Parses section headers  
- Computes entropy for each section  
- Applies simple heuristics like NOP‑sled detection  
- Falls back to whole‑file heuristics if section parsing fails  

---

## Core Types and Structures

### ELF Type Aliases
Basic 64‑bit integer and word types mirror the ELF specification:

- `Elf64_Addr`
- `Elf64_Off`
- `Elf64_Half`
- `Elf64_Word`
- `Elf64_Xword`
- `Elf64_Sxword`

These ensure correct sizes and alignment for header parsing.

### ELF Header (`TElf64_Ehdr`)
Contains the file identity `e_ident` (including magic `0x7F 'E' 'L' 'F'` and class), entry point, program/section header offsets and sizes, and counts.  
The code checks this header to confirm the file is ELF64 and to locate section headers.

### Section Header (`TElf64_Shdr`)
Describes each section:

- Name index (`sh_name`)
- Type
- Flags (e.g., executable)
- Memory address
- File offset
- Size
- Alignment
- Entry size  

The scanner iterates these to read and analyze each section’s bytes.

---

## Key Helper Functions

- **`ReadBytesToBuffer`**: Reads `Size` bytes from a stream at `Offset` into a dynamic byte array. Returns `True` only if a full read succeeds.  
- **`IsElf64`**: Confirms the file is a valid ELF64 by checking the magic and the class byte (`e_ident[4] = 2`).  
- **`Entropy`**: Computes Shannon entropy in bits/byte for a buffer:

  

\[
  H = -\sum_{i=0}^{255} p_i \cdot \log_2(p_i)
  \]



  - Entropy near 8 → high randomness (packing/encryption)  
  - Lower values → structured code/data  

- **`HasNOPSled`**: Scans for runs of `0x90` (x86 NOP) of at least `MinRun` length.  
- **`ReadStringFrom`**: Converts a null‑terminated string from a string table buffer starting at `Offset`. Used to resolve human‑readable section names.

---

## Analysis Flow

### Input and ELF Validation
1. **Open file**: Creates a `TFileStream` for the target binary.  
2. **Read ELF header**: Validates size and format with `IsElf64`. If invalid, raises an error and triggers fallback.

### Section String Table Resolution
- **Locate `shstrtab`**: Uses `e_shoff`, `e_shentsize`, and `e_shstrndx`.  
- **Load `shstrtab`**: Reads the entire string table into memory for name resolution via `ReadStringFrom`.

### Section Iteration and Metrics
- **Loop sections**: Resolve `ShName`, skip empty sections, read bytes with `ReadBytesToBuffer`.  
- **Compute metrics**:
  - **Entropy**: Quantifies randomness  
  - **Exec flag**: Checks `SHF_EXECINSTR`  
  - **NOP sled**: Detects long runs of `0x90`  
  - **High entropy flag**: Marks entropy > 7.2 with size > 1 KiB as suspicious  

---

## Heuristics and Reporting

### Suspicion Triggers
- Executable + high entropy → possible packed/encrypted code  
- NOP sled in code or `.text` → shellcode/exploit preparation  
- Non‑standard exec section → suspicious if not named `.text` but sizable with elevated entropy  

### Output
- Prints per‑section summary (name, size, entropy, flags, indicators)  
- Aggregates a final **“potential embedded code detected”** message if heuristics trip  

---

## Fallback Whole‑File Heuristics
If section parsing fails (malformed ELF):

- Reads entire file into buffer  
- Computes whole‑file entropy  
- Looks for very long NOP sleds  

Less precise than per‑section analysis but still highlights anomalies.

---

## Compilation and Usage

```bash
# Compile on Linux
fpc -O2 ElfSecurityScanner.pas

# Run
./ElfSecurityScanner /path/to/binary

-----


Here’s your text converted into clean **GitHub-flavored Markdown** with headings, lists, and code blocks for clarity:

```markdown
# How to Compile on Linux

## Install Free Pascal
- **Debian/Ubuntu**:  
  ```bash
  sudo apt-get install fpc
  ```
- **Fedora**:  
  ```bash
  sudo dnf install fpc
  ```
- **Arch**:  
  ```bash
  sudo pacman -S fpc
  ```

---

## Save the Code
Save the source code to a file named:

```bash
ElfSecurityScanner.pas
```

---

## Compile
```bash
fpc -O2 ElfSecurityScanner.pas
```

---

## Run
```bash
./ElfSecurityScanner /path/to/binary
```

---

## Optional Flags

### Static Linking (if supported by your distro)
```bash
-XX -Xs
```
- Strips and smartlinks the binary  
- Note: static linking may require additional setup  

### 32-bit Target (if needed)
```bash
-Parm -Tlinux
```
- Requires appropriate 32‑bit Free Pascal libraries installed  
```

Would you like me to also **add a “Quick Reference Table”** summarizing the commands per distro and optional flags so it’s easier to scan at a glance?
