/*
  Nik built-in YARA rules. Each rule carries `severity` ("high" or "medium")
  and `description` in its meta: the UI reads both. Keep rules conservative:
  a false positive here colours a sample red for every analyst.
*/

rule upx_packed
{
    meta:
        description = "UPX packer section names or signature"
        severity = "medium"
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
        $s4 = "$Info: This file is packed with the UPX executable packer" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule pe_process_injection_apis
{
    meta:
        description = "Imports the classic process injection API chain"
        severity = "high"
    strings:
        $a1 = "VirtualAllocEx" ascii
        $a2 = "WriteProcessMemory" ascii
        $a3 = "CreateRemoteThread" ascii
        $a4 = "NtCreateThreadEx" ascii
        $a5 = "QueueUserAPC" ascii
        $a6 = "SetThreadContext" ascii
    condition:
        uint16(0) == 0x5A4D and ($a1 and $a2 and ($a3 or $a4 or $a5 or $a6))
}

rule pe_anti_debug
{
    meta:
        description = "Debugger and sandbox detection APIs"
        severity = "medium"
    strings:
        $d1 = "IsDebuggerPresent" ascii
        $d2 = "CheckRemoteDebuggerPresent" ascii
        $d3 = "NtQueryInformationProcess" ascii
        $d4 = "OutputDebugStringA" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule powershell_encoded_command
{
    meta:
        description = "PowerShell launched with an encoded or hidden payload"
        severity = "high"
    strings:
        $p1 = "powershell" ascii wide nocase
        $e1 = "-EncodedCommand" ascii wide nocase
        $e2 = " -enc " ascii wide nocase
        $e3 = "FromBase64String" ascii wide nocase
        $h1 = "-WindowStyle Hidden" ascii wide nocase
        $h2 = " -w hidden" ascii wide nocase
    condition:
        $p1 and (1 of ($e*) or 1 of ($h*))
}

rule ransomware_note_wording
{
    meta:
        description = "Ransom note wording and shadow copy deletion"
        severity = "high"
    strings:
        $r1 = "your files have been encrypted" ascii wide nocase
        $r2 = "decrypt your files" ascii wide nocase
        $r3 = "vssadmin delete shadows" ascii wide nocase
        $r4 = "wbadmin delete catalog" ascii wide nocase
        $r5 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
    condition:
        2 of them
}

rule credential_dumping_tools
{
    meta:
        description = "Strings of credential dumping tooling"
        severity = "high"
    strings:
        $m1 = "mimikatz" ascii wide nocase
        $m2 = "sekurlsa::logonpasswords" ascii wide nocase
        $m3 = "lsadump::" ascii wide nocase
        $m4 = "gentilkiwi" ascii wide nocase
        $l1 = "lsass.exe" ascii wide nocase
        $l2 = "MiniDumpWriteDump" ascii
    condition:
        1 of ($m*) or ($l1 and $l2)
}

rule elf_reverse_shell_hints
{
    meta:
        description = "ELF with shell spawning and socket connect strings"
        severity = "medium"
    strings:
        $s1 = "/bin/sh" ascii
        $s2 = "/bin/bash" ascii
        $c1 = "connect" ascii
        $c2 = "socket" ascii
        $d1 = "dup2" ascii
    condition:
        uint32(0) == 0x464C457F and 1 of ($s*) and $c1 and $c2 and $d1
}

rule macho_encrypted_or_antidebug
{
    meta:
        description = "Mach-O with ptrace anti-debugging"
        severity = "medium"
    strings:
        $p1 = "ptrace" ascii
        $p2 = "PT_DENY_ATTACH" ascii
        $s1 = "sysctl" ascii
    condition:
        (uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE) and ($p1 or $p2) and $s1
}

rule office_macro_autoopen
{
    meta:
        description = "Office document with auto-executing macro keywords"
        severity = "medium"
    strings:
        $m1 = "AutoOpen" ascii wide nocase
        $m2 = "Auto_Open" ascii wide nocase
        $m3 = "Document_Open" ascii wide nocase
        $m4 = "Workbook_Open" ascii wide nocase
        $v1 = "vbaProject.bin" ascii
        $v2 = "VBA" ascii
    condition:
        (uint32(0) == 0xE011CFD0 or uint32(0) == 0x04034B50) and 1 of ($m*) and 1 of ($v*)
}

rule pdf_javascript_launch
{
    meta:
        description = "PDF with JavaScript, Launch or OpenAction"
        severity = "medium"
    strings:
        $j1 = "/JavaScript" ascii
        $j2 = "/JS" ascii
        $l1 = "/Launch" ascii
        $o1 = "/OpenAction" ascii
        $a1 = "/AA" ascii
    condition:
        uint32(0) == 0x46445025 and (($j1 or $j2) and ($o1 or $a1) or $l1)
}
