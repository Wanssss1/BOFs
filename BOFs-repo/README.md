# BOFs

Beacon Object Files (BOFs) for Cobalt Strike and Havoc C2. Implementations of Active Directory attacks and post-exploitation techniques.

> **Note:** This code was developed using my knowledge of Windows internals, Kerberos, and Active Directory, with assistance from Claude Code. It is the researcher's responsibility to understand and improve the code according to their needs.

## Offensive BOFs

| BOF | Description | Attack Chain |
|-----|-------------|--------------|
| [ESC1-unPAC](./ESC1-unPAC) | ADCS ESC1 exploitation | ESC1 → PKINIT → UnPAC-the-hash |
| [ShadowCredsBOF](./ShadowCredsBOF) | Shadow Credentials attack | KeyCredential → PKINIT → NT Hash |
| [IHxExec-BOF](./IHxExec-BOF) | Cross-session command execution | IHxHelpPaneServer COM hijacking |

## Learning BOFs

| BOF | Description |
|-----|-------------|
| [CustomBOFs](./CustomBOFs) | Basic enumeration BOFs for learning purposes (whoami, LDAP queries, share finder, ESC1 finder) |

## Quick Reference

### ESC1-unPAC
```bash
# Build
cd ESC1-unPAC && ./build.sh

# Usage
esc1-unpac CA\\CAName TemplateName user@domain.local
```

### ShadowCredsBOF
```bash
# Build
cd ShadowCredsBOF && make bof

# Usage
shadowcreds TargetUser domain.local
```

### IHxExec-BOF
```bash
# Build
cd IHxExec-BOF && ./build.sh

# Usage
sessions
ihxexec <session_id> C:\path\to\binary.exe
```
