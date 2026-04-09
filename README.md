WannaCry V2 Malware Analysis & Reverse Engineering
Overview

This project presents a reverse engineering and behavioral analysis of the WannaCry V2 ransomware. The analysis focuses on execution flow, persistence mechanisms, filesystem behavior, and cryptographic preparation using static analysis techniques.

WannaCry is a ransomware worm that gained global attention due to its ability to spread automatically across vulnerable systems using SMB exploits.

Objectives
Analyze WannaCry V2 payload behavior
Identify persistence and execution mechanisms
Examine filesystem staging and encryption preparation
Extract Indicators of Compromise (IOCs)
Develop a behavioral YARA detection rule

Key Findings
Service-Based Persistence
Uses Windows Service Control Manager APIs:
OpenSCManagerA
CreateServiceA
StartServiceA
Executes payload via:
cmd.exe /c

Enables persistence and elevated execution

Process Execution
Launches payload using cmd.exe
Supports flexible command-based execution
Filesystem Staging
Uses:
CreateDirectoryA
GetFileAttributesA
Implements recursive directory creation

Ensures reliable staging of ransomware components

Cryptographic Validation
Enforces strict buffer sizes:
16 bytes (128-bit)
24 bytes (192-bit)
32 bytes (256-bit)
Uses structured exception handling (_CxxThrowException)

Indicates controlled encryption workflow

Multi-Threaded Execution
Uses synchronization primitives:
DeleteCriticalSection

Suggests concurrent execution for performance (encryption + propagation)

Masquerading
Observed executable name:
diskpart.exe

Mimics legitimate Windows utility to evade detection

Indicators of Compromise (IOCs)
File Indicators
diskpart.exe (suspicious executable name)
Encrypted file extensions:
.WNCRY
.WCRY
Process Indicators
cmd.exe executing unknown payloads
Service-launched processes from unusual paths
Service Indicators
Newly created Windows services
Service execution paths containing:
cmd.exe /c

Network Indicators
SMB traffic on port 445
Internal scanning behavior
Behavioral Indicators
Recursive directory creation
Rapid file modification / encryption
Multi-threaded activity
Service-based persistence

MITRE ATT&CK Mapping
Tactic	Technique
Persistence	T1543.003 – Windows Service
Execution	T1059.003 – Command Shell
Defense Evasion	T1036 – Masquerading
Impact	T1486 – Data Encrypted for Impact
Lateral Movement	T1021.002 – SMB

Tools Used
Ghidra (reverse engineering)
OS REMnux

YARA Detection Rule
rule WannaCry_V2_Payload_Behavioral
{
    meta:
        author = "Tyler"
        description = "Detects WannaCry-style payload behavior"
    
    strings:
        $cmd = "cmd.exe /c" ascii wide
        $svc1 = "CreateServiceA" ascii
        $svc2 = "StartServiceA" ascii
        $dir = "CreateDirectoryA" ascii
        $mask = "diskpart.exe" ascii wide
        $crypto = "_CxxThrowException" ascii
    
    condition:
        uint16(0) == 0x5A4D and
        $cmd and 2 of ($svc*) and 1 of ($dir,$mask,$crypto)
}


Kali Linux / Ubuntu Pro (analysis environment)
