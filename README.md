# BOFs

Beacon Object Files (BOFs) for Cobalt Strike and Havoc C2. Implementations of Active Directory attacks and post-exploitation techniques.

> **Note:** This code was developed using my knowledge of Windows internals, Kerberos, and Active Directory, with assistance from Claude Code. It is the researcher's responsibility to understand and improve the code according to their needs.

## Offensive BOFs

| BOF | Description | Attack Chain |
|-----|-------------|--------------|
| [ESC1-unPAC](./ESC1-unPAC) | ADCS ESC1 exploitation | ESC1 → PKINIT → UnPAC-the-hash |
| [ShadowCredsBOF](./ShadowCreds-unPAC-BOF) | Shadow Credentials attack | Write target msDS-KeyCredentialLink → PKINIT → UnPAC-the-hash → Clear target msDS-KeyCredentialLink |
| [IHxExec-BOF](./IHxExec-BOF) | Cross-session command execution | IHxHelpPaneServer COM hijacking |

## Learning BOFs

| BOF | Description |
|-----|-------------|
| [CustomBOFs](./CustomBOFs) | Basic enumeration BOFs for learning purposes (whoami, LDAP queries, share finder, ESC1 finder) |

**Credits:** References to the original researchers and community projects are included in each BOF's README.
