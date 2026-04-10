# WannaCry V2 Malware Analysis & Reverse Engineering

This project presents a reverse engineering and behavioral analysis of the WannaCry V2 ransomware. The analysis focuses on execution flow, persistence mechanisms, filesystem behavior, and cryptographic preparation using static analysis techniques.

WannaCry is a ransomware worm that gained global attention due to its ability to spread automatically across vulnerable systems using SMB exploits.

---

## Objectives
- Analyze WannaCry V2 payload behavior  
- Identify persistence and execution mechanisms  
- Examine filesystem staging and encryption preparation  
- Extract Indicators of Compromise (IoCs)  
- Develop a behavioral YARA detection rule  

---

## Execution Flow Summary
1. Initial execution via `cmd.exe /c`  
2. Establishes persistence using Windows services  
3. Creates directories for staging payload components  
4. Prepares encryption routines  
5. Executes multi-threaded operations  

---

## Key Findings

### Service-Based Persistence
Uses Windows Service Control Manager APIs:
- `OpenSCManagerA`
- `CreateServiceA`
- `StartServiceA`

Executes payload via:
- `cmd.exe /c`

This enables persistence and elevated execution through service-based mechanisms.

---

### Process Execution
- Launches payload using `cmd.exe`  
- Supports flexible command-based execution  

This suggests modular execution behavior and adaptability.

---

### Filesystem Staging
Uses:
- `CreateDirectoryA`
- `GetFileAttributesA`

Implements recursive directory creation, ensuring reliable staging of ransomware components.

---

### Cryptographic Preparation
Enforces strict buffer sizes:
- 16 bytes (128-bit)  
- 24 bytes (192-bit)  
- 32 bytes (256-bit)  

Uses `_CxxThrowException`, indicating structured exception handling within the C++ runtime.

This suggests controlled handling of encryption-related operations.

---

### Multi-Threaded Execution
Uses synchronization primitives:
- `DeleteCriticalSection`

Indicates concurrent execution, likely for parallel encryption and propagation.

---

### Masquerading
Observed executable name:
- `diskpart.exe`

This mimics a legitimate Windows utility to evade detection.

---

## Indicators of Compromise (IoCs)

### File Indicators
- `diskpart.exe` (suspicious executable name)  
- Encrypted file extensions: `.WNCRY`, `.WCRY`  

---

### Process Indicators
- `cmd.exe` executing unknown payloads  
- Service-launched processes from unusual paths  

---

### Service Indicators
- Newly created Windows services  
- Execution paths containing `cmd.exe /c`  

---

### Network Indicators
- SMB traffic on port 445  
- Internal scanning behavior  

---

### Behavioral Indicators
- Recursive directory creation  
- Rapid file modification / encryption  
- Multi-threaded activity  
- Service-based persistence  

---

## MITRE ATT&CK Mapping

| Tactic            | Technique                                      |
|------------------|-----------------------------------------------|
| Persistence      | T1543.003 – Windows Service                   |
| Execution        | T1059.003 – Command Shell                     |
| Defense Evasion  | T1036 – Masquerading                          |
| Impact           | T1486 – Data Encrypted for Impact             |
| Lateral Movement | T1021.002 – SMB                              |

---

## Tools Used
- Ghidra (reverse engineering)  
- REMnux (analysis environment)  
- Kali Linux / Ubuntu Pro  

---

## YARA Detection Rule

```yara
rule WannaCry_V2_Payload_Behavioral {
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
