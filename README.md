
## User-mode-security-tool

Overview
This program is a user‑mode ELF scanner for Linux that inspects a binary’s sections and reports potential indicators of embedded or obfuscated code. It validates the ELF64 header, parses section headers, computes entropy for each section, and applies simple heuristics like NOP‑sled detection. When section parsing fails, it falls back to whole‑file heuristics so you still get a signal instead of a hard failure.

Core types and structures
ELF type aliases: Basic 64‑bit integer and word types mirror the ELF specification: Elf64_Addr, Elf64_Off, Elf64_Half, Elf64_Word, Elf64_Xword, and Elf64_Sxword. These ensure correct sizes and alignment for header parsing.
ELF header (TElf64_Ehdr): Contains the file identity e_ident (including magic 0x7F 'E' 'L' 'F' and class), entry point, program/section header offsets and sizes, and counts. The code checks this header to confirm the file is ELF64 and to locate section headers.
Section header (TElf64_Shdr): Describes each section: name index (sh_name), type, flags (e.g., executable), memory address, file offset, size, alignment, and entry size. The scanner iterates these to read and analyze each section’s bytes.

Key helper functions
ReadBytesToBuffer: Reads Size bytes from a stream at Offset into a dynamic byte array. Returns True only if a full read succeeds, which prevents partial reads from corrupting analysis.
IsElf64: Confirms the file is a valid ELF64 by checking the magic and the class byte (e_ident[4] = 2).
Entropy: Computes Shannon entropy in bits/byte for a buffer by counting byte frequencies and applying: [ H = -\sum_{i=0}^{255} p_i \cdot \log_2(p_i) ] Entropy near (8) suggests high randomness (often packing/encryption), while lower values suggest structured code/data.
HasNOPSled: Scans for runs of 0x90 (x86 NOP) of at least MinRun length, a classic shellcode preparation pattern. It returns early on detection for efficiency.
ReadStringFrom: Converts a null‑terminated string from a string table buffer starting at Offset. Used to resolve human‑readable section names from sh_name indices.

Analysis flow
Input and ELF validation
Open file: Creates a TFileStream for the target binary.
Read ELF header: Validates size and format with IsElf64. If invalid, raises an error and later triggers fallback.
Section string table resolution
Locate shstrtab: Uses e_shoff, e_shentsize, and e_shstrndx to read the section header of the string table (names for sections).
Load shstrtab: Reads the entire string table into memory for name resolution via ReadStringFrom.
Section iteration and metrics
Loop sections: For each section header, resolve ShName, skip empty sections, and read its bytes using ReadBytesToBuffer.
Compute metrics:
Entropy: Quantifies randomness of section contents.
Exec flag: Checks SHF_EXECINSTR to know if the section likely contains code.
NOP sled: Detects long runs of 0x90.
High entropy flag: Marks entropy above 7.2 with size > 1 KiB as suspicious.
Heuristics and reporting
Suspicion triggers:
Executable + high entropy: Possible packed or encrypted code.
NOP sled in code or .text: Indicative of shellcode or exploit preparation.
Non‑standard exec section: Executable section not named like .text with sizable content and elevated entropy.
Output: Prints per‑section summary (name, size, entropy, flags) and indicators. Aggregates a final “potential embedded code detected” message if any section trips heuristics.

Fallback whole‑file heuristics
If section parsing fails (e.g., malformed ELF), the program reads the entire file into a buffer. It computes whole‑file entropy and looks for very long NOP sleds. This won’t be as precise as per‑section analysis but can still highlight strong anomalies.

Compilation and usage
Compile on Linux:
fpc -O2 ElfSecurityScanner.pas
Run:
./ElfSecurityScanner /path/to/binary
Notes:
Performance: -O2 helps; you can add -Xs (strip) or -XX (smartlink) depending on your environment.
Architecture: This scanner assumes ELF64; extend IsElf64 and header parsing to support ELF32 if needed.

Design choices, limits, and extensions
Design choices:


Entropy threshold: (>7.2) bits/byte for sections, balancing false positives against packed code detection.
NOP sled run length: 32 in sections (strict) and 64 for whole‑file to reduce noise.
Limitations:


ELF64 only: No 32‑bit support in this snippet.
Static heuristics: No dynamic analysis, symbol resolution, or program header inspection.
Architecture assumptions: NOP sled detection targets x86/x86_64; other ISAs have different patterns.
Easy extensions:


Signature checks: Search for known packer markers (e.g., “UPX!”) or encoder strings and flag them.
Section anomalies: Warn on RWX sections, nameless exec sections, very small exec sections, or misalignment (low sh_addralign).
Sliding window entropy: Compute entropy over windows (e.g., 4 KiB) to catch localized payloads.
Program headers: Inspect PT_LOAD segments for RWX mappings and alignment issues.
Imports and dynamics: Parse PT_DYNAMIC and .dynsym for unusual loader behavior.
