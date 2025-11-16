

{$mode objfpc}{$H+}
{$packrecords c}

uses
  SysUtils, Classes, Math;

type
  Elf64_Addr = QWord;
  Elf64_Off  = QWord;
  Elf64_Half = Word;
  Elf64_Word = Cardinal;
  Elf64_Xword = QWord;
  Elf64_Sxword = Int64;

  TElf64_Ehdr = packed record
    e_ident: array[0..15] of Byte; // 0x7F 'E' 'L' 'F'
    e_type: Elf64_Half;
    e_machine: Elf64_Half;
    e_version: Elf64_Word;
    e_entry: Elf64_Addr;
    e_phoff: Elf64_Off;
    e_shoff: Elf64_Off;
    e_flags: Elf64_Word;
    e_ehsize: Elf64_Half;
    e_phentsize: Elf64_Half;
    e_phnum: Elf64_Half;
    e_shentsize: Elf64_Half;
    e_shnum: Elf64_Half;
    e_shstrndx: Elf64_Half;
  end;

  TElf64_Shdr = packed record
    sh_name: Elf64_Word;
    sh_type: Elf64_Word;
    sh_flags: Elf64_Xword;
    sh_addr: Elf64_Addr;
    sh_offset: Elf64_Off;
    sh_size: Elf64_Xword;
    sh_link: Elf64_Word;
    sh_info: Elf64_Word;
    sh_addralign: Elf64_Xword;
    sh_entsize: Elf64_Xword;
  end;

const
  ELF_MAGIC: array[0..3] of Byte = ($7F, Ord('E'), Ord('L'), Ord('F'));
  // Section flags (from System V ABI)
  SHF_WRITE      = QWord($1);
  SHF_ALLOC      = QWord($2);
  SHF_EXECINSTR  = QWord($4);

function ReadBytesToBuffer(Stream: TStream; Offset: Int64; Size: Int64; out Buf: TBytes): Boolean;
begin
  Result := False;
  SetLength(Buf, Size);
  Stream.Position := Offset;
  if Stream.Read(Buf[0], Size) = Size then
    Result := True;
end;

function IsElf64(const H: TElf64_Ehdr): Boolean;
begin
  Result :=
    (H.e_ident[0] = ELF_MAGIC[0]) and
    (H.e_ident[1] = ELF_MAGIC[1]) and
    (H.e_ident[2] = ELF_MAGIC[2]) and
    (H.e_ident[3] = ELF_MAGIC[3]) and
    (H.e_ident[4] = 2); // 2 = 64-bit (ELFCLASS64)
end;

// Shannon entropy (bits/byte) for a byte buffer
function Entropy(const Buf: TBytes): Double;
var
  freq: array[0..255] of Double;
  i: Integer;
  p, H: Double;
begin
  for i := 0 to 255 do freq[i] := 0.0;
  for i := 0 to High(Buf) do Inc(freq[Buf[i]]);
  H := 0.0;
  if Length(Buf) = 0 then Exit(0.0);
  for i := 0 to 255 do
  begin
    if freq[i] > 0 then
    begin
      p := freq[i] / Length(Buf);
      H := H - p * (Ln(p) / Ln(2)); // log2
    end;
  end;
  Result := H;
end;

// Detect simple NOP sleds (x86/x86_64: 0x90 repeated)
function HasNOPSled(const Buf: TBytes; MinRun: Integer = 16): Boolean;
var
  i, run: Integer;
begin
  Result := False;
  run := 0;
  for i := 0 to High(Buf) do
  begin
    if Buf[i] = $90 then
    begin
      Inc(run);
      if run >= MinRun then Exit(True);
    end
    else
      run := 0;
  end;
end;

function ReadStringFrom(const Buf: TBytes; Offset: Cardinal): AnsiString;
var
  i: Cardinal;
begin
  Result := '';
  i := Offset;
  while (i < Cardinal(Length(Buf))) and (Buf[i] <> 0) do
  begin
    Result := Result + AnsiChar(Buf[i]);
    Inc(i);
  end;
end;

procedure AnalyzeELF(const FileName: string);
var
  FS: TFileStream;
  Ehdr: TElf64_Ehdr;
  Shdr: TElf64_Shdr;
  i: Integer;
  ShStrTab: TBytes;
  ShName: AnsiString;
  SectionBuf: TBytes;
  Ent: Double;
  Suspicious: Boolean;
  ExecFlag: Boolean;
  HighEntropy: Boolean;
  NOPSled: Boolean;
  AnySuspicious: Boolean;
begin
  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    if FS.Read(Ehdr, SizeOf(Ehdr)) <> SizeOf(Ehdr) then
      raise Exception.Create('Failed to read ELF header');
    if not IsElf64(Ehdr) then
      raise Exception.Create('Not an ELF64 file or invalid magic');

    // Read section header string table
    if (Ehdr.e_shstrndx = 0) or (Ehdr.e_shoff = 0) then
      raise Exception.Create('ELF section headers missing');

    // Load shstrtab section header
    FS.Position := Ehdr.e_shoff + Int64(Ehdr.e_shentsize) * Ehdr.e_shstrndx;
    if FS.Read(Shdr, SizeOf(Shdr)) <> SizeOf(Shdr) then
      raise Exception.Create('Failed to read shstrtab header');
    if not ReadBytesToBuffer(FS, Shdr.sh_offset, Shdr.sh_size, ShStrTab) then
      raise Exception.Create('Failed to read shstrtab');

    Writeln('File: ', FileName);
    Writeln('Sections: ', Ehdr.e_shnum);
    Writeln('---');

    AnySuspicious := False;

    // Iterate sections
    for i := 0 to Ehdr.e_shnum - 1 do
    begin
      FS.Position := Ehdr.e_shoff + Int64(Ehdr.e_shentsize) * i;
      if FS.Read(Shdr, SizeOf(Shdr)) <> SizeOf(Shdr) then
        raise Exception.Create('Failed to read section header');

      ShName := ReadStringFrom(ShStrTab, Shdr.sh_name);
      if (Shdr.sh_size = 0) then
        continue;

      // Read section contents
      if not ReadBytesToBuffer(FS, Shdr.sh_offset, Shdr.sh_size, SectionBuf) then
        continue;

      // Metrics
      Ent := Entropy(SectionBuf);
      ExecFlag := (Shdr.sh_flags and SHF_EXECINSTR) <> 0;
      HighEntropy := (Ent > 7.2) and (Length(SectionBuf) > 1024); // heuristic
      NOPSled := HasNOPSled(SectionBuf, 32); // stricter sled length

      Suspicious := False;
      // Heuristics
      // 1) Executable + high entropy (likely packed/obfuscated)
      if ExecFlag and HighEntropy then Suspicious := True;
      // 2) NOP sleds in executable or .text sections
      if (ExecFlag or (ShName = '.text')) and NOPSled then Suspicious := True;
      // 3) Non-standard executable section names with code-like size
      if ExecFlag and (Pos('.text', ShName) = 0) and (Length(SectionBuf) > 4096) and (Ent > 6.5) then Suspicious := True;

      // Report
      Writeln(Format('Section %-20s size=%d bytes, entropy=%.3f, flags=%s%s',
        [String(ShName), Length(SectionBuf), Ent,
         IfThen((Shdr.sh_flags and SHF_ALLOC) <> 0, 'ALLOC ', ''),
         IfThen(ExecFlag, 'EXEC ', '')]));

      if NOPSled then
        Writeln('  -> Indicator: NOP sled detected');
      if HighEntropy then
        Writeln('  -> Indicator: High entropy (possible packing/encryption)');

      if Suspicious then
      begin
        AnySuspicious := True;
        Writeln('  => Suspicious section flagged');
      end;
    end;

    Writeln('---');
    if AnySuspicious then
      Writeln('Result: Potential embedded or obfuscated code detected')
    else
      Writeln('Result: No strong indicators of embedded code found');

  finally
    FS.Free;
  end;
end;

procedure ScanWholeFileHeuristics(const FileName: string);
var
  FS: TFileStream;
  Buf: TBytes;
  Ent: Double;
  NOPSled: Boolean;
begin
  // Fallback: whole-file scan (useful for stripped binaries or malformed ELF)
  FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Buf, FS.Size);
    if FS.Read(Buf[0], FS.Size) <> FS.Size then
      raise Exception.Create('Failed to read file');

    Ent := Entropy(Buf);
    NOPSled := HasNOPSled(Buf, 64);

    Writeln('Whole-file entropy: ', FormatFloat('0.000', Ent));
    if NOPSled then
      Writeln('Indicator: Long NOP sled detected (file-level)');
  finally
    FS.Free;
  end;
end;

begin
  if ParamCount < 1 then
  begin
    Writeln('Usage: ElfSecurityScanner <path/to/file>');
    Halt(1);
  end;

  try
    AnalyzeELF(ParamStr(1));
  except
    on E: Exception do
    begin
      Writeln('ELF analysis error: ', E.Message);
      Writeln('Falling back to whole-file heuristics...');
      try
        ScanWholeFileHeuristics(ParamStr(1));
      except
        on E2: Exception do
          Writeln('Fallback error: ', E2.Message);
      end;
    end;
  end;
end.
