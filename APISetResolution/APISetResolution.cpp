#include <windows.h>
#include <stdio.h>
#include "Structs.h"
#include "APIs.h"

/*
 * Given an api set name, returns the lenght of the string (in words) until the last hyphen.
 *
 * @param[in] apiSetName api set name.
 * @return  computed length.
 */
WORD getCleanedSize(IN PWCHAR apiSetName) {
    PWCHAR LastHyphen = wcsrchr(apiSetName, L'-');
    return LastHyphen - apiSetName;
}


/*
 * Hash function used for the hash table.
 *
 * @param[in] ApiNameToResolve api set name to resolve.
 * @param[in] ApiNameToResolveSize size of the api set name to resolve.
 * @param[in] HashFactor factor used by the function. Sort of hashing key using.
 * @return  computed hash.
 */
ULONG hash(IN PWCHAR ApiNameToResolve, IN WORD ApiNameToResolveSize, IN ULONG HashFactor) {
    ULONG HashKey = 0;
    for (size_t i = 0; i < ApiNameToResolveSize; i++) {
        HashKey = HashKey * HashFactor + toLower(ApiNameToResolve[i]);
    }
    return HashKey;
}


/*
 * Retrieve the hash entry at a specific index.
 *
 * @param[in] ApiNamespace the address of the .apiset section.
 * @param[in] entryIndex index of the hash entry to retrieve.
 * @return  the pointer to the right hash entry.
 */
PAPI_SET_HASH_ENTRY getHashEntryAtindex(IN PAPI_SET_NAMESPACE ApiNamespace, IN int hashIndex) {
    PAPI_SET_HASH_ENTRY hashTable = (PAPI_SET_HASH_ENTRY)((ULONG_PTR)ApiNamespace + ApiNamespace->HashOffset);
    return &(hashTable[hashIndex]);
}


/*
 * Retrieve the name space entry at a specific index.
 *
 * @param[in] ApiNamespace the address of the .apiset section.
 * @param[in] entryIndex index of the namespace entry to retrieve.
 * @return  the pointer to the right namespace entry.
 */
PAPI_SET_NAMESPACE_ENTRY getNamespaceEntryAtindex(IN PAPI_SET_NAMESPACE ApiNamespace, IN int entryIndex) {
    PAPI_SET_NAMESPACE_ENTRY entryTable = (PAPI_SET_NAMESPACE_ENTRY)((ULONG_PTR)ApiNamespace + ApiNamespace->EntryOffset);
    return &(entryTable[entryIndex]);
}


/*
 * Retrieve the value entry (for a namespace entry) at a specific index.
 *
 * @param[in] ApiNamespace the address of the .apiset section.
 * @param[in] namespaceEntry the namespace entry that contains the value entry.
 * @param[in] entryIndex index of the value entry to retrieve.
 * @return  the pointer to the right value entry.
 */
PAPI_SET_VALUE_ENTRY getValueEntryAtindex(IN PAPI_SET_NAMESPACE ApiNamespace, IN PAPI_SET_NAMESPACE_ENTRY namespaceEntry, IN int entryIndex) {
    PAPI_SET_VALUE_ENTRY entryTable = (PAPI_SET_VALUE_ENTRY)((ULONG_PTR)ApiNamespace + namespaceEntry->ValueOffset);
    return &(entryTable[entryIndex]);
}


/*
 * Retrieve the namespace entry relative to an api set, performing a search on the hash table.
 *
 * @param[in] ApiNamespace the address of the .apiset section.
 * @param[in] ApiNameToResolve api set name to resolve.
 * @param[in] ApiNameToResolveSize size of the api set name to resolve.
 * @return  the pointer to the right namespace entry.
 */
PAPI_SET_NAMESPACE_ENTRY ApiSetpSearchForApiSet(IN PAPI_SET_NAMESPACE ApiNamespace, IN PWCHAR ApiNameToResolve, IN WORD ApiNameToResolveSize) {
    int up, down = 0, hashIndex;
    ULONG hashKey;
    PAPI_SET_HASH_ENTRY pHashKeyCurr;
    API_SET_NAMESPACE_ENTRY* foundEntry = NULL;

    if (!ApiNamespace  || !ApiNameToResolveSize || !ApiNameToResolve)
        return NULL;

    up = ApiNamespace->Count - 1;
    
    if (up < 0)
        return NULL;
    
    hashKey = hash(ApiNameToResolve, ApiNameToResolveSize, ApiNamespace->HashFactor);

    // binary search (don't hash tables have O(1) average time complexity?)
    do {
        hashIndex = (down + up)/2;
        pHashKeyCurr = getHashEntryAtindex(ApiNamespace, hashIndex);
        
        if (hashKey == pHashKeyCurr->Hash)
            break;
        if (hashKey < pHashKeyCurr->Hash) {
            up = hashIndex - 1;
        }
        else {
            down = hashIndex + 1;
        }
    } while (down <= up);

    if (down > up)
        return NULL;
    
    foundEntry = getNamespaceEntryAtindex(ApiNamespace, pHashKeyCurr->Index);
    if (!foundEntry)
        return NULL;

    // confirm that right hash entry is found by comparing the api set name
    if (memcmp((PWCHAR)((ULONG_PTR)ApiNamespace + foundEntry->NameOffset), ApiNameToResolve, ApiNameToResolveSize*2) == 0) {
        return foundEntry;
    }
    return NULL;
}



/*
 * Performs 2nd step resolution when an entry refers to multiple host dlls.
 * I didn't test this function. 
 *
 * @param[in] Entry the entry retrieved with {@link #ApiSetpSearchForApiSet()}.
 * @param[in] ParentName dunno, set it to NULL.
 * @param[in] ParentNameLen len of dunno.
 * @param[in] ApiNamespace the address of the .apiset section.
 * @return  the pointer to the right value entry.
 */
PAPI_SET_VALUE_ENTRY ApiSetpSearchForApiSetHost( IN PAPI_SET_NAMESPACE_ENTRY Entry, IN PWCHAR ParentName, IN SHORT ParentNameLen, IN PAPI_SET_NAMESPACE ApiNamespace){
    int down, up, entryAliasIndex;
    PAPI_SET_VALUE_ENTRY aliasEntry;
    if (Entry->ValueCount == 1)
        return (PAPI_SET_VALUE_ENTRY)((ULONG_PTR)ApiNamespace + Entry->ValueOffset);


    down = 1;
    up = Entry->ValueCount - 1;

    do {
        entryAliasIndex = (down + up) / 2;
        aliasEntry = getValueEntryAtindex(ApiNamespace, Entry, entryAliasIndex);
        // if aliasEntry is right
        // no check on the lenght, could be a bug
        int cmpResult = strcmpLowerW(ParentName, (LPWSTR)((ULONG_PTR)ApiNamespace) + aliasEntry->NameOffset);

        if (cmpResult == 0) {
            return aliasEntry;
        }
        else {
            if (cmpResult < 0) {
                up = entryAliasIndex - 1;
            }
            else {
                down = entryAliasIndex + 1;
            }
        }
    } while (down <= up);

    if (down > up)
        return NULL;
}


/*
 * Resolve an api set string. Reimplementation of the NTDLL function.
 *
 * @param[in] ApiNamespace the address of the .apiset section.
 * @param[in] ApiToResolve the api set to resolve.
 * @param[in] ParentName dunno, set it to NULL.
 * @param[out] Resolved it becomes true if the resolution succeded, false otherwise.
 * @param[out] Output it will contain the resolved host dll.
 * @return  always STATUS_SUCCESS. Use {@code Resolved} to known if resolution succeded.
 */
NTSTATUS ApiSetResolveToHost(IN PAPI_SET_NAMESPACE ApiNamespace, IN PUNICODE_STRING ApiToResolve, IN PUNICODE_STRING ParentName, OUT PBOOLEAN Resolved, OUT PUNICODE_STRING Output) {
    BOOL isResolved = FALSE;
    if (ApiToResolve->Length >= 8) {
        if (
            (ApiToResolve->Buffer[0] == L'a' && ApiToResolve->Buffer[1] == L'p' && ApiToResolve->Buffer[2] == L'i' && ApiToResolve->Buffer[3] == L'-') ||
            (ApiToResolve->Buffer[0] == L'e' && ApiToResolve->Buffer[1] == L'x' && ApiToResolve->Buffer[2] == L't' && ApiToResolve->Buffer[3] == L'-')
            ) {
            WORD ApiSetNameWithoutExtensionWordCount = getCleanedSize(ApiToResolve->Buffer);
            if (ApiSetNameWithoutExtensionWordCount) {
                PAPI_SET_NAMESPACE_ENTRY resolvedEntry = ApiSetpSearchForApiSet(ApiNamespace, ApiToResolve->Buffer, ApiSetNameWithoutExtensionWordCount);
                PAPI_SET_VALUE_ENTRY hostLibraryEntry;
                if (resolvedEntry) {
                    if (ParentName && resolvedEntry->ValueCount > 1) {
                        hostLibraryEntry = ApiSetpSearchForApiSetHost(resolvedEntry, ParentName->Buffer, ParentName->Length, ApiNamespace);
                    }
                    else {
                        if (resolvedEntry->ValueCount > 0) {
                            hostLibraryEntry = (PAPI_SET_VALUE_ENTRY) ((ULONG_PTR)ApiNamespace + resolvedEntry->ValueOffset);
                        }
                        else {
                            goto EPILOGUE;
                        }
                    }
                    isResolved = TRUE;
                    Output->Buffer = (PWSTR)((ULONG_PTR)ApiNamespace + hostLibraryEntry->ValueOffset);
                    Output->MaximumLength = (USHORT)hostLibraryEntry->ValueLength;
                    Output->Length = (USHORT)hostLibraryEntry->ValueLength;
                }
            }
        }
    }
EPILOGUE:
    *Resolved = isResolved;
    return STATUS_SUCCESS;
}


/*
 * Retrieve ApiSetMap from PEB.
 *
 * @return	value of PEB.ApiSetMap.
 */
PAPI_SET_NAMESPACE getApiSetMap() {
    PPEB					pPeb = (PEB*)(__readgsqword(0x60));
    return pPeb->ApiSetMap;
}


/*
 * Resolve an ApiSet name.
 *
 * @param[in] apiSetName the name of the api set to resolve.
 * @param[out] resolvedDll the resolved name.
 * @return	true if succeded, false otherwise.
 */
BOOL resolveApiSet(IN PWSTR apiSetName, OUT PWSTR resolvedDll) {
    USHORT apiSetLen = wcslen(apiSetName);
    if (apiSetLen == 0)
        return FALSE;

    NTSTATUS status;
    UNICODE_STRING ApiToResolve, output;
    BOOLEAN resolved = FALSE;

    ApiToResolve.Buffer = apiSetName;
    ApiToResolve.Length = apiSetLen * sizeof(WCHAR);
    ApiToResolve.MaximumLength = ApiToResolve.Length + sizeof(WCHAR);

    
    status = ApiSetResolveToHost(getApiSetMap(), &ApiToResolve, NULL, &resolved, &output);

    if (status != STATUS_SUCCESS || !resolved)
        return FALSE;

    // need to reallocate the resolved name since it can be non-terminated by null charachter
    memcpy(resolvedDll, output.Buffer, output.Length);
    resolvedDll[output.Length / 2] = 0;
    return TRUE;
}


int main()
{
    PAPI_SET_NAMESPACE_ENTRY entry;
    wchar_t api1[] = L"api-ms-win-base-util-l1-1-0.dll";
    wchar_t api2[] = L"api-ms-win-core-com-l1-1-3.dll";
    wchar_t api3[] = L"api-ms-win-core-crt-l1-1-0.dll";
    wchar_t api4[] = L"api-ms-win-ole32-ie-l1-1-0.dll";
    wchar_t resolvedDll[MAX_PATH];

    if (resolveApiSet(api1, resolvedDll)) {
        printf("[+] %S -> %S\n", api1, resolvedDll);
    }
    else {
        printf("[!] Error resolving api set %S\n", api1);
    }
    if (resolveApiSet(api2, resolvedDll)) {
        printf("[+] %S -> %S\n", api2, resolvedDll);
    }
    else {
        printf("[!] Error resolving api set %S\n", api2);
    }
    if (resolveApiSet(api3, resolvedDll)) {
        printf("[+] %S -> %S\n", api3, resolvedDll);
    }
    else {
        printf("[!] Error resolving api set %S\n", api3);
    }
    if (resolveApiSet(api4, resolvedDll)) {
        printf("[+] %S -> %S\n", api4, resolvedDll);
    }
    else {
        printf("[!] Error resolving api set %S\n", api4);
    }
    return 0;
}
