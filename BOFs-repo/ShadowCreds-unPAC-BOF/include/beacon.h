/*
 * Beacon Object File (BOF) - Header File
 *
 * Compatible with Cobalt Strike 4.x and Havoc C2
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* Note: LPUNKNOWN and other COM types are defined in the main source file
 * before including this header in BOF mode */

/*
 * Dynamic Function Resolution (DFR) Macros
 * These macros declare functions that will be resolved at runtime
 */

#ifdef BOF

/* DFR declarations for KERNEL32 */
DECLSPEC_IMPORT void* WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
DECLSPEC_IMPORT LPSTR WINAPI KERNEL32$lstrcpyA(LPSTR, LPCSTR);
DECLSPEC_IMPORT LPWSTR WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenA(LPCSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT void WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SystemTimeToFileTime(const SYSTEMTIME*, LPFILETIME);

/* DFR declarations for ADVAPI32 */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptExportKey(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetProvParam(HCRYPTPROV, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptSignHashW(HCRYPTHASH, DWORD, LPCWSTR, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsValidSid(PSID);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);

/* DFR declarations for CRYPT32 */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertStrToNameA(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptEncodeObjectEx(DWORD, LPCSTR, const void*, DWORD, PCRYPT_ENCODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptExportPublicKeyInfo(HCRYPTPROV, DWORD, DWORD, PCERT_PUBLIC_KEY_INFO, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptSignAndEncodeCertificate(HCRYPTPROV, DWORD, DWORD, LPCSTR, const void*, PCRYPT_ALGORITHM_IDENTIFIER, const void*, BYTE*, DWORD*);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertSetCertificateContextProperty(PCCERT_CONTEXT, DWORD, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertAddCertificateContextToStore(HCERTSTORE, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT*);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$PFXExportCertStoreEx(HCERTSTORE, CRYPT_DATA_BLOB*, LPCWSTR, void*, DWORD);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$PFXImportCertStore(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT, DWORD, void*, HCRYPTPROV*, DWORD*, BOOL*);
DECLSPEC_IMPORT HCRYPTMSG WINAPI CRYPT32$CryptMsgOpenToEncode(DWORD, DWORD, DWORD, const void*, LPSTR, PCMSG_STREAM_INFO);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgUpdate(HCRYPTMSG, const BYTE*, DWORD, BOOL);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgGetParam(HCRYPTMSG, DWORD, DWORD, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgClose(HCRYPTMSG);

/* DFR declarations for OLE32 */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);

/* DFR declarations for WLDAP32 */
DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR WINAPI WLDAP32$ldap_get_dnW(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT void WINAPI WLDAP32$ldap_memfreeW(PWSTR);
DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_modify_sW(LDAP*, PWSTR, LDAPModW*[]);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, const void*);

/* DFR declarations for NETAPI32 */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* DFR declarations for WS2_32 */
DECLSPEC_IMPORT int WINAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WINAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET WINAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WINAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WINAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT struct hostent* WINAPI WS2_32$gethostbyname(const char*);
DECLSPEC_IMPORT unsigned long WINAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT u_short WINAPI WS2_32$htons(u_short);
DECLSPEC_IMPORT u_long WINAPI WS2_32$htonl(u_long);
DECLSPEC_IMPORT u_long WINAPI WS2_32$ntohl(u_long);

/* DFR declarations for MSVCRT */
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, size_t, const wchar_t*, ...);
DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int);
DECLSPEC_IMPORT int __cdecl MSVCRT$rand(void);
DECLSPEC_IMPORT time_t __cdecl MSVCRT$time(time_t*);

/* Function mappings for BOF mode */
#define HeapAlloc KERNEL32$HeapAlloc
#define HeapFree KERNEL32$HeapFree
#define GetProcessHeap KERNEL32$GetProcessHeap
#define GetSystemTime KERNEL32$GetSystemTime
#define GetSystemTimeAsFileTime KERNEL32$GetSystemTimeAsFileTime
#define LoadLibraryA KERNEL32$LoadLibraryA
#define FreeLibrary KERNEL32$FreeLibrary
#define GetProcAddress KERNEL32$GetProcAddress
#define GetLastError KERNEL32$GetLastError
#define SetLastError KERNEL32$SetLastError
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte
#define lstrcpyA KERNEL32$lstrcpyA
#define lstrcpyW KERNEL32$lstrcpyW
#define lstrcmpW KERNEL32$lstrcmpW
#define lstrlenA KERNEL32$lstrlenA
#define lstrlenW KERNEL32$lstrlenW
#define CreateFileA KERNEL32$CreateFileA
#define CloseHandle KERNEL32$CloseHandle
#define WriteFile KERNEL32$WriteFile
#define ReadFile KERNEL32$ReadFile
#define Sleep KERNEL32$Sleep
#define SystemTimeToFileTime KERNEL32$SystemTimeToFileTime

#define CryptAcquireContextW ADVAPI32$CryptAcquireContextW
#define CryptReleaseContext ADVAPI32$CryptReleaseContext
#define CryptGenKey ADVAPI32$CryptGenKey
#define CryptDestroyKey ADVAPI32$CryptDestroyKey
#define CryptExportKey ADVAPI32$CryptExportKey
#define CryptImportKey ADVAPI32$CryptImportKey
#define CryptGetProvParam ADVAPI32$CryptGetProvParam
#define CryptCreateHash ADVAPI32$CryptCreateHash
#define CryptHashData ADVAPI32$CryptHashData
#define CryptGetHashParam ADVAPI32$CryptGetHashParam
#define CryptDestroyHash ADVAPI32$CryptDestroyHash
#define CryptGenRandom ADVAPI32$CryptGenRandom
#define CryptSignHashW ADVAPI32$CryptSignHashW
#define ConvertSidToStringSidA ADVAPI32$ConvertSidToStringSidA
#define IsValidSid ADVAPI32$IsValidSid
#define GetLengthSid ADVAPI32$GetLengthSid

#define CertStrToNameA CRYPT32$CertStrToNameA
#define CryptEncodeObjectEx CRYPT32$CryptEncodeObjectEx
#define CryptDecodeObjectEx CRYPT32$CryptDecodeObjectEx
#define CryptExportPublicKeyInfo CRYPT32$CryptExportPublicKeyInfo
#define CryptSignAndEncodeCertificate CRYPT32$CryptSignAndEncodeCertificate
#define CertOpenStore CRYPT32$CertOpenStore
#define CertCloseStore CRYPT32$CertCloseStore
#define CertCreateCertificateContext CRYPT32$CertCreateCertificateContext
#define CertFreeCertificateContext CRYPT32$CertFreeCertificateContext
#define CertSetCertificateContextProperty CRYPT32$CertSetCertificateContextProperty
#define CertAddCertificateContextToStore CRYPT32$CertAddCertificateContextToStore
#define CertEnumCertificatesInStore CRYPT32$CertEnumCertificatesInStore
#define PFXExportCertStoreEx CRYPT32$PFXExportCertStoreEx
#define PFXImportCertStore CRYPT32$PFXImportCertStore
#define CryptBinaryToStringA CRYPT32$CryptBinaryToStringA
#define CryptStringToBinaryA CRYPT32$CryptStringToBinaryA
#define CryptAcquireCertificatePrivateKey CRYPT32$CryptAcquireCertificatePrivateKey
#define CryptMsgOpenToEncode CRYPT32$CryptMsgOpenToEncode
#define CryptMsgUpdate CRYPT32$CryptMsgUpdate
#define CryptMsgGetParam CRYPT32$CryptMsgGetParam
#define CryptMsgClose CRYPT32$CryptMsgClose

#define CoInitializeEx OLE32$CoInitializeEx
#define CoUninitialize OLE32$CoUninitialize
#define CoCreateGuid OLE32$CoCreateGuid
#define CoCreateInstance OLE32$CoCreateInstance

#define ldap_initW WLDAP32$ldap_initW
#define ldap_bind_sW WLDAP32$ldap_bind_sW
#define ldap_unbind WLDAP32$ldap_unbind
#define ldap_search_sW WLDAP32$ldap_search_sW
#define ldap_first_entry WLDAP32$ldap_first_entry
#define ldap_get_dnW WLDAP32$ldap_get_dnW
#define ldap_memfreeW WLDAP32$ldap_memfreeW
#define ldap_get_values_lenW WLDAP32$ldap_get_values_lenW
#define ldap_value_free_len WLDAP32$ldap_value_free_len
#define ldap_msgfree WLDAP32$ldap_msgfree
#define ldap_modify_sW WLDAP32$ldap_modify_sW
#define ldap_set_optionW WLDAP32$ldap_set_optionW

#define DsGetDcNameW NETAPI32$DsGetDcNameW
#define NetApiBufferFree NETAPI32$NetApiBufferFree

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

#define malloc MSVCRT$malloc
#define free MSVCRT$free
#define memcpy MSVCRT$memcpy
#define memset MSVCRT$memset
#define memcmp MSVCRT$memcmp
#define strlen MSVCRT$strlen
#define strcpy MSVCRT$strcpy
#define strcat MSVCRT$strcat
#define strcmp MSVCRT$strcmp
#define wcslen MSVCRT$wcslen
#define wcscpy MSVCRT$wcscpy
#define wcscat MSVCRT$wcscat
#define sprintf MSVCRT$sprintf
#define swprintf MSVCRT$swprintf
#define srand MSVCRT$srand
#define rand MSVCRT$rand
#define time MSVCRT$time

/*
 * Beacon API Functions
 */

/* Data parsing */
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

DECLSPEC_IMPORT void BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT char* BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT int BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int BeaconDataLength(datap* parser);

/* Output */
DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char* data, int len);

/* Format */
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} formatp;

DECLSPEC_IMPORT void BeaconFormatAlloc(formatp* format, int maxsz);
DECLSPEC_IMPORT void BeaconFormatReset(formatp* format);
DECLSPEC_IMPORT void BeaconFormatFree(formatp* format);
DECLSPEC_IMPORT void BeaconFormatAppend(formatp* format, char* text, int len);
DECLSPEC_IMPORT void BeaconFormatPrintf(formatp* format, char* fmt, ...);
DECLSPEC_IMPORT char* BeaconFormatToString(formatp* format, int* size);
DECLSPEC_IMPORT void BeaconFormatInt(formatp* format, int value);

/* Token */
DECLSPEC_IMPORT BOOL BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL BeaconIsAdmin(void);

/* Spawn/Inject */
DECLSPEC_IMPORT void BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
DECLSPEC_IMPORT void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);

/* Utility */
DECLSPEC_IMPORT BOOL toWideChar(char* src, wchar_t* dst, int max);

#endif /* BOF */

#endif /* BEACON_H */
