#ifndef UNICODE
  #define UNICODE
#endif

#include <stdio.h> // sprintf
#include <stdint.h> // uint32_t, uint64_t
#include <string.h> // strncat
#include <Windows.h> // Windows API
#include <winbase.h> // OpenFile
#include <fileapi.h> // ReadFile
#include <errhandlingapi.h> // GetLastError
#include <wchar.h> // Wide-caracters
#include <WinError.h> // Syscall Errors

#include "mft.h" // MFT structs

// Mode

#define MODE_SUMMARY 1
#define MODE_CSV 2
#define MODE_PATHS 3
#define MODE_VERBOSE 4

int output_mode = 0;

// Helper functions

void ErrorExit(wchar_t* name){
    DWORD err_code = GetLastError();
    TCHAR* formattedStringBuffer = NULL;

    // https://learn.microsoft.com/es-es/windows/win32/api/winbase/nf-winbase-formatmessage
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &formattedStringBuffer,
        0,
        NULL
    );

    wprintf(L"Error at %s (%d): %sBye!", (wchar_t*) name, err_code, (wchar_t*) formattedStringBuffer);
    LocalFree(formattedStringBuffer); // Free the allocated buffer
    exit(err_code);
}

char* AttributeTypeCodeToName(ATTRIBUTE_TYPE_CODE type_code){
    // https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header#members
    switch (type_code){
        case 0x10:
            return "$STANDARD_INFORMATION";
            break;
        case 0x20:
            return "$ATTRIBUTE_LIST";
            break;
        case 0x30:
            return "$FILE_NAME";
            break;
        case 0x40:
            return "$OBJECT_ID";
            break;
        case 0x50:
            return "$SECURITY_DESCRIPTOR";
            break;
        case 0x60:
            return "$VOLUME_NAME";
            break;
        case 0x70:
            return "$VOLUME_INFORMATION";
            break;
        case 0x80:
            return "$DATA";
            break;
        case 0x90:
            return "$INDEX_ROOT";
            break;
        case 0xA0:
            return "$INDEX_ALLOCATION";
            break;
        case 0xB0:
            return "$BITMAP";
            break;
        case 0xC0:
            return "$SYMBOLIC_LINK";
            break;
        case 0xD0:
            return "$EA_INFORMATION";
            break;
        case 0xE0:
            return "$EA";
            break;
        case 0xF0:
            return "$PROPERTY_SET";
            break;
        case 0x100:
            return "$FIRST_USER_DEFINED_ATTRIBUTE";
            break;
        case 0xFFFFFFFF:
            return "$END";
            break;
        default:
            return "Unknown";
            break;
    }
}

void PrintStringLen(char* String, int Length){
    char* NullEndedString = (char*) malloc((Length + 1) * sizeof(char));
    strncpy(NullEndedString, String, Length);
    strncpy(NullEndedString + Length, "\0", 1);
    printf("%s", NullEndedString);
    free(NullEndedString);
}

void PrintWideStringLen(wchar_t* WString, int Length){
    wchar_t* NullEndedWString = (wchar_t*) malloc((Length + 1) * sizeof(wchar_t));
    wcsncpy(NullEndedWString, WString, Length);
    wcsncpy(NullEndedWString + Length, L"\0", 1);
    wprintf(L"%s", NullEndedWString);
    free(NullEndedWString);
}

// Print Object functions

void PrintFileRecordSegmentHeader(FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader){
    printf("[+] File Record Segment Header:\r\n");
    printf(" * Signature: %s\r\n", FileRecordSegmentHeader->MultiSectorHeader.Signature);
    printf(" * UpdateSequenceArrayOffset: %d\r\n", FileRecordSegmentHeader->MultiSectorHeader.UpdateSequenceArrayOffset);
    printf(" * UpdateSequenceArraySize: %d\r\n", FileRecordSegmentHeader->MultiSectorHeader.UpdateSequenceArraySize);
    printf(" * Lsn (Log File Sequence Number): %lld\r\n", FileRecordSegmentHeader->Lsn);
    printf(" * SequenceNumber: %d\r\n", FileRecordSegmentHeader->SequenceNumber);
    printf(" * ReferenceCount: %d\r\n", FileRecordSegmentHeader->ReferenceCount);
    printf(" * FirstAttributeOffset: %d\r\n", FileRecordSegmentHeader->FirstAttributeOffset);
    printf(" * Flags: %d\r\n", FileRecordSegmentHeader->Flags);
    if(FileRecordSegmentHeader->Flags & FILE_RECORD_SEGMENT_IN_USE) printf("   - File Record Segment is in use.\r\n");
    if(FileRecordSegmentHeader->Flags & FILE_FILE_NAME_INDEX_PRESENT) printf("   - File Name Index is present.\r\n");

    printf(" * FirstFreeByte: %d\r\n", FileRecordSegmentHeader->FirstFreeByte);
    printf(" * BytesAvailable: %d\r\n", FileRecordSegmentHeader->BytesAvailable);
    printf(" * BaseFileRecordSegment.SegmentNumberLowPart: %d\r\n", FileRecordSegmentHeader->BaseFileRecordSegment.SegmentNumberLowPart);
    printf(" * BaseFileRecordSegment.SegmentNumberHighPart: %d\r\n", FileRecordSegmentHeader->BaseFileRecordSegment.SegmentNumberHighPart);
    printf(" * BaseFileRecordSegment.SequenceNumber: %d\r\n", FileRecordSegmentHeader->BaseFileRecordSegment.SequenceNumber);
    printf(" * NextAttributeInstance: %d\r\n", FileRecordSegmentHeader->NextAttributeInstance);
}

void PrintStandardInformationAttributeValue(STANDARD_INFORMATION* StandardInformationAttributeValue){
    char CreationTime[32];
    char LastModificationTime[32];
    char LastChangeTime[32];
    char LastAccessTime[32];

    SYSTEMTIME stUTC;

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->CreationTime, &stUTC);
    sprintf(CreationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastModificationTime, &stUTC);
    sprintf(LastModificationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastChangeTime, &stUTC);
    sprintf(LastChangeTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastAccessTime, &stUTC);
    sprintf(LastAccessTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    printf("   * CreationTime: %s (%lld)\r\n", CreationTime, StandardInformationAttributeValue->CreationTime);
    printf("   * LastModificationTime: %s (%lld)\r\n", LastModificationTime, StandardInformationAttributeValue->LastModificationTime);
    printf("   * LastChangeTime: %s (%lld)\r\n", LastChangeTime, StandardInformationAttributeValue->LastChangeTime);
    printf("   * LastAccessTime: %s (%lld)\r\n", LastAccessTime, StandardInformationAttributeValue->LastAccessTime);

    printf("   * FileAttributes: %d\r\n", StandardInformationAttributeValue->FileAttributes);
    printf("   * MaximumVersions: %d\r\n", StandardInformationAttributeValue->MaximumVersions);
    printf("   * VersionNumber: %d\r\n", StandardInformationAttributeValue->VersionNumber);

}

void PrintDuplicatedInformation(DUPLICATED_INFORMATION* DuplicatedInformation){

    char CreationTime[32];
    char LastModificationTime[32];
    char LastChangeTime[32];
    char LastAccessTime[32];

    SYSTEMTIME stUTC;

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->CreationTime, &stUTC);
    sprintf(CreationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->LastModificationTime, &stUTC);
    sprintf(LastModificationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->LastChangeTime, &stUTC);
    sprintf(LastChangeTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->LastAccessTime, &stUTC);
    sprintf(LastAccessTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    printf("   * Info.CreationTime: %s (%lld)\r\n", CreationTime, DuplicatedInformation->CreationTime);
    printf("   * Info.LastModificationTime: %s (%lld)\r\n", LastModificationTime, DuplicatedInformation->LastModificationTime);
    printf("   * Info.LastChangeTime: %s (%lld)\r\n", LastChangeTime, DuplicatedInformation->LastChangeTime);
    printf("   * Info.LastAccessTime: %s (%lld)\r\n", LastAccessTime, DuplicatedInformation->LastAccessTime);

    printf("   * Info.AllocatedLength: %lld\r\n", DuplicatedInformation->AllocatedLength);
    printf("   * Info.FileSize: %lld\r\n", DuplicatedInformation->FileSize);
    printf("   * Info.FileAttributes: %d\r\n", DuplicatedInformation->FileAttributes);
    printf("   * Info.PackedEaSize: %d\r\n", DuplicatedInformation->PackedEaSize);
    printf("   * Info.Reserved: %d\r\n", DuplicatedInformation->Reserved);
}

void PrintFileNameAttributeValue(FILE_NAME* FileNameAttributeValue){
    
    printf("   * ParentDirectory.SegmentNumberLowPart: %d\r\n", FileNameAttributeValue->ParentDirectory.SegmentNumberLowPart);
    printf("   * ParentDirectory.SegmentNumberHighPart: %d\r\n", FileNameAttributeValue->ParentDirectory.SegmentNumberHighPart);
    printf("   * ParentDirectory.SequenceNumber: %d\r\n", FileNameAttributeValue->ParentDirectory.SequenceNumber);

    PrintDuplicatedInformation((DUPLICATED_INFORMATION*) &FileNameAttributeValue->Info);

    printf("   * FileNameLength: %d\r\n", FileNameAttributeValue->FileNameLength);
    printf("   * Flags: %d\r\n", FileNameAttributeValue->Flags);
    if (FileNameAttributeValue->Flags & FILE_NAME_NTFS) printf("     - The file name is in Unicode (NTFS-compatible format).\r\n");
    if (FileNameAttributeValue->Flags & FILE_NAME_DOS) printf("     - The file name is in DOS-compatible format.\r\n");

    printf("   * FileName: ");
    PrintWideStringLen(FileNameAttributeValue->FileName, FileNameAttributeValue->FileNameLength);

    printf("\r\n");
}

void PrintAttributeRecordHeader(ATTRIBUTE_RECORD_HEADER* AttributeRecordHeader){
    printf("[+] Attribute Record Header:\r\n");

    printf(" * TypeCode: 0x%x (%s)\r\n", AttributeRecordHeader->TypeCode, AttributeTypeCodeToName(AttributeRecordHeader->TypeCode));
    printf(" * RecordLength: %d\r\n", AttributeRecordHeader->RecordLength);
    printf(" * FormCode: %d\r\n", AttributeRecordHeader->FormCode);
    if(AttributeRecordHeader->FormCode == RESIDENT_FORM) printf("   - Resident Form\r\n");
    if(AttributeRecordHeader->FormCode == NONRESIDENT_FORM) printf("   - Nonresident Form\r\n");
    
    printf(" * NameLength: %d\r\n", AttributeRecordHeader->NameLength);
    printf(" * NameOffset: %d\r\n", AttributeRecordHeader->NameOffset);
    if (AttributeRecordHeader->NameLength > 0) {
        printf("   - Name: ");
        PrintWideStringLen((wchar_t*) ((char*) AttributeRecordHeader + AttributeRecordHeader->NameOffset), AttributeRecordHeader->NameLength);
        printf("\r\n");
    }

    printf(" * Flags: %d\r\n", AttributeRecordHeader->Flags);
    if (AttributeRecordHeader->Flags & ATTRIBUTE_FLAG_COMPRESSION_MASK)     printf("   - Compression Mask: %d\r\n", AttributeRecordHeader->Flags & ATTRIBUTE_FLAG_COMPRESSION_MASK);
    if (AttributeRecordHeader->Flags & ATTRIBUTE_FLAG_SPARSE)               printf("   - Sparse\r\n");
    if (AttributeRecordHeader->Flags & ATTRIBUTE_FLAG_ENCRYPTED)            printf("   - Encrypted\r\n");

    printf(" * Instance: %d\r\n", AttributeRecordHeader->Instance);

    if (AttributeRecordHeader->FormCode == RESIDENT_FORM) {
        printf(" * Form.Resident.ValueLength: %d\r\n", AttributeRecordHeader->Form.Resident.ValueLength);
        printf(" * Form.Resident.ValueOffset: %d\r\n", AttributeRecordHeader->Form.Resident.ValueOffset);
        printf(" * Form.Resident.ResidentFlags: %d\r\n", AttributeRecordHeader->Form.Resident.ResidentFlags);
        printf(" * Form.Resident.Reserved: %d\r\n", AttributeRecordHeader->Form.Resident.Reserved);
    }
    else if (AttributeRecordHeader->FormCode == NONRESIDENT_FORM) {
        printf(" * Form.Nonresident.LowestVcn: %lld\r\n", AttributeRecordHeader->Form.Nonresident.LowestVcn);
        printf(" * Form.Nonresident.HighestVcn: %lld\r\n", AttributeRecordHeader->Form.Nonresident.HighestVcn);
        printf(" * Form.Nonresident.MappingPairsOffset: %d\r\n", AttributeRecordHeader->Form.Nonresident.MappingPairsOffset);
        printf(" * Form.Nonresident.CompressionUnit: %d\r\n", AttributeRecordHeader->Form.Nonresident.CompressionUnit);
        printf(" * Form.Nonresident.AllocatedLength: %lld\r\n", AttributeRecordHeader->Form.Nonresident.AllocatedLength);
        printf(" * Form.Nonresident.FileSize: %lld\r\n", AttributeRecordHeader->Form.Nonresident.FileSize);
        printf(" * Form.Nonresident.ValidDataLength: %lld\r\n", AttributeRecordHeader->Form.Nonresident.ValidDataLength);
        printf(" * Form.Nonresident.TotalAllocated: %lld\r\n", AttributeRecordHeader->Form.Nonresident.TotalAllocated);
    }

    if (AttributeRecordHeader->Form.Resident.ValueLength > 0) {

        char* AttributeValue = (char*)(AttributeRecordHeader) + AttributeRecordHeader->Form.Resident.ValueOffset;

        printf(" + Attribute Value:\r\n");

        if (AttributeRecordHeader->TypeCode == $STANDARD_INFORMATION)
            PrintStandardInformationAttributeValue((STANDARD_INFORMATION*) AttributeValue);
        
        else if (AttributeRecordHeader->TypeCode == $FILE_NAME) 
            PrintFileNameAttributeValue((FILE_NAME*) AttributeValue);

    }
}

// Summary Print Object functions

void PrintSummaryFileRecordSegmentHeader(FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader){
    printf("\n[+] {File Record Segment} [sig:%s|sn:%d|refs:%d|flags:%d]\r\n",
        FileRecordSegmentHeader->MultiSectorHeader.Signature,
        FileRecordSegmentHeader->SequenceNumber,
        FileRecordSegmentHeader->ReferenceCount,
        FileRecordSegmentHeader->Flags
    );
}

void PrintSummaryStandardInformationAttributeValue(STANDARD_INFORMATION* StandardInformationAttributeValue){
    char CreationTime[32];
    char LastModificationTime[32];
    char LastChangeTime[32];
    char LastAccessTime[32];

    SYSTEMTIME stUTC;

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->CreationTime, &stUTC);
    sprintf(CreationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastModificationTime, &stUTC);
    sprintf(LastModificationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastChangeTime, &stUTC);
    sprintf(LastChangeTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastAccessTime, &stUTC);
    sprintf(LastAccessTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    printf("   - [file-attrs:%d|max-ver:%d|ver:%d|M:%s|A:%s|C:%s|b:%s]\r\n",
        StandardInformationAttributeValue->FileAttributes,
        StandardInformationAttributeValue->MaximumVersions,
        StandardInformationAttributeValue->VersionNumber,
        LastModificationTime,
        LastAccessTime,
        LastChangeTime,
        CreationTime
    );
}

void PrintSummaryDuplicatedInformation(DUPLICATED_INFORMATION* DuplicatedInformation){
    char CreationTime[32];
    char LastModificationTime[32];
    char LastChangeTime[32];
    char LastAccessTime[32];

    SYSTEMTIME stUTC;

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->CreationTime, &stUTC);
    sprintf(CreationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->LastModificationTime, &stUTC);
    sprintf(LastModificationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->LastChangeTime, &stUTC);
    sprintf(LastChangeTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &DuplicatedInformation->LastAccessTime, &stUTC);
    sprintf(LastAccessTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    printf("   - [file-size:%lld|M:%s|A:%s|C:%s|b:%s]\r\n",
        DuplicatedInformation->FileSize,
        LastModificationTime,
        LastAccessTime,
        LastChangeTime,
        CreationTime
    );
}

void PrintSummaryFileNameAttributeValue(FILE_NAME* FileNameAttributeValue){
    wprintf(L"   - [name:");
    PrintWideStringLen(FileNameAttributeValue->FileName, FileNameAttributeValue->FileNameLength);
    printf("|len:%d", FileNameAttributeValue->FileNameLength);
    printf("|flags:0x%x", FileNameAttributeValue->Flags);
    if (FileNameAttributeValue->Flags != 0) {
        printf("(");
        if (FileNameAttributeValue->Flags & FILE_NAME_DOS) printf("DOS,");
        if (FileNameAttributeValue->Flags & FILE_NAME_NTFS) printf("NTFS,");
        printf("\b)"); // Removes the last comma
    }
    printf("]\r\n");
    PrintSummaryDuplicatedInformation((DUPLICATED_INFORMATION*) &FileNameAttributeValue->Info);
}

void PrintSummaryAttributeRecordHeader(ATTRIBUTE_RECORD_HEADER* AttributeRecordHeader){
    if (AttributeRecordHeader->FormCode == RESIDENT_FORM) {
        printf(" * Resident Attribute %s [type:0x%x|len:%d|flags:%d|res-len:%d|res-flags:%d]\r\n",
            AttributeTypeCodeToName(AttributeRecordHeader->TypeCode),
            AttributeRecordHeader->TypeCode,
            AttributeRecordHeader->RecordLength,
            AttributeRecordHeader->Flags,
            AttributeRecordHeader->Form.Resident.ValueLength,
            AttributeRecordHeader->Form.Resident.ResidentFlags
        );
    }
    else if (AttributeRecordHeader->FormCode == NONRESIDENT_FORM) {
        printf(" * Non-resident Attribute %s [type:0x%x|len:%d|flags:%d|vcn:%lld-%lld|compress:%d|alloc-len:%lld|file-size:%lld]\r\n",
            AttributeTypeCodeToName(AttributeRecordHeader->TypeCode),
            AttributeRecordHeader->TypeCode, AttributeRecordHeader->RecordLength,
            AttributeRecordHeader->Flags,
            AttributeRecordHeader->Form.Nonresident.LowestVcn,
            AttributeRecordHeader->Form.Nonresident.HighestVcn,
            AttributeRecordHeader->Form.Nonresident.CompressionUnit,
            AttributeRecordHeader->Form.Nonresident.AllocatedLength,
            AttributeRecordHeader->Form.Nonresident.FileSize
        );
    }
}

// Attribute Getter functions

ATTRIBUTE_RECORD_HEADER* GetStandardInformationAttribute(FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader){
        
        int AttributeOffset = FileRecordSegmentHeader->FirstAttributeOffset;
        while (1) {
            ATTRIBUTE_RECORD_HEADER* AttrRecordHeader = (ATTRIBUTE_RECORD_HEADER*) ((char*) FileRecordSegmentHeader + AttributeOffset);
            if (AttrRecordHeader->TypeCode == $STANDARD_INFORMATION) {
                return AttrRecordHeader;
            }
            if (AttrRecordHeader->TypeCode == $END) break;
            if (AttrRecordHeader->TypeCode == $UNUSED) break;
            if ((USHORT) AttrRecordHeader->RecordLength == 0) break; // TODO: Properly fix this type casting hack
    
            AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
        }
        return NULL;
}

ATTRIBUTE_RECORD_HEADER* GetFirstDOSFileNameAttribute(FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader){
    
    int AttributeOffset = FileRecordSegmentHeader->FirstAttributeOffset;

    while (1) {
        ATTRIBUTE_RECORD_HEADER* AttrRecordHeader = (ATTRIBUTE_RECORD_HEADER*) ((char*) FileRecordSegmentHeader + AttributeOffset);
        if (AttrRecordHeader->TypeCode == $FILE_NAME) {
            return AttrRecordHeader;
            FILE_NAME* FileName = (FILE_NAME*) ((char*) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset);
            if (FileName->Flags & FILE_NAME_DOS) {
                return AttrRecordHeader;
            }
        }
        if (AttrRecordHeader->TypeCode == $END) break;
        if (AttrRecordHeader->TypeCode == $UNUSED) break;
        if ((USHORT) AttrRecordHeader->RecordLength == 0) break; // TODO: Properly fix this type casting hack

        AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
    }

    return NULL;
}

ATTRIBUTE_RECORD_HEADER* GetFirstMostNTFSFileNameAttribute(FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader){
    
    // It is essential that this is a USHORT and not int, as it can break things when added as offset.
    USHORT AttributeOffset = FileRecordSegmentHeader->FirstAttributeOffset;

    ATTRIBUTE_RECORD_HEADER* ReturnedAttrRecordHeader = NULL;
    UCHAR ReturnedFlags = 0;

    while (1) {
        ATTRIBUTE_RECORD_HEADER* AttrRecordHeader = (ATTRIBUTE_RECORD_HEADER*) ((char*) FileRecordSegmentHeader + AttributeOffset);

        if (AttrRecordHeader->TypeCode == $FILE_NAME) {
            FILE_NAME* FileName = (FILE_NAME*) ((char*) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset);

            // Always save the first one.
            if(ReturnedAttrRecordHeader == NULL) {
                ReturnedAttrRecordHeader = AttrRecordHeader;
                ReturnedFlags = FileName->Flags;
            }
            
            // If past flags where DOS-only and current are NTFS (or DOS+NTFS), save new one
            if (!(ReturnedFlags & FILE_NAME_NTFS) && FileName->Flags & FILE_NAME_NTFS) {
                ReturnedAttrRecordHeader = AttrRecordHeader;
                ReturnedFlags = FileName->Flags;
            }
            
            // If past flags where DOS (or DOS+NTFS) and current are NTFS only, save new one
            if (ReturnedFlags & FILE_NAME_DOS && !(FileName->Flags & FILE_NAME_DOS)) {
                ReturnedAttrRecordHeader = AttrRecordHeader;
                ReturnedFlags = FileName->Flags;
            }
        }
        if (AttrRecordHeader->TypeCode == $END) break;
        if (AttrRecordHeader->TypeCode == $UNUSED) break;
        if ((USHORT) AttrRecordHeader->RecordLength == 0) break; // TODO: Properly fix this type casting hack

        AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
    }

    return ReturnedAttrRecordHeader;
}

// Path resolution functions

void PrintFilePath(FILE_NAME* FileNameAttributeValue, char* Buffer, uint64_t BufferSize){

    uint32_t ParentMFTEntry = FileNameAttributeValue->ParentDirectory.SegmentNumberLowPart;
    FILE_RECORD_SEGMENT_HEADER* ParentFileRecordSegmentHeader = (FILE_RECORD_SEGMENT_HEADER*) ((char*) Buffer + ParentMFTEntry * FILE_RECORD_SEGMENT_SIZE);
    ATTRIBUTE_RECORD_HEADER* ParentFileNameAttribute = GetFirstMostNTFSFileNameAttribute(ParentFileRecordSegmentHeader);
    FILE_NAME* ParentFileNameAttributeValue = (FILE_NAME*) ((char*) ParentFileNameAttribute + ParentFileNameAttribute->Form.Resident.ValueOffset);

    if (ParentMFTEntry == 5) {
        printf("\\"); // 5: root directory (\) // https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table
        PrintWideStringLen(FileNameAttributeValue->FileName, FileNameAttributeValue->FileNameLength);
        return; // Ends deepening into the recursion
    }
    // Recursive resolution
    PrintFilePath(ParentFileNameAttributeValue, Buffer, BufferSize);
    printf("\\");
    PrintWideStringLen(FileNameAttributeValue->FileName, FileNameAttributeValue->FileNameLength);
}

void PrintSummaryFilePath(FILE_NAME* FileNameAttributeValue, char* Buffer, uint64_t BufferSize){
    printf("   - [path:");
    PrintFilePath(FileNameAttributeValue, Buffer, BufferSize);
    printf("]\r\n");
}

// Attribute Value Fields Reader functions

void ReadStandardInformationAttributeValueFields(ATTRIBUTE_RECORD_HEADER* StandardInformationAttribute, char** Creation, char** LastModification, char** LastChange, char** LastAccess){
    
    *Creation = (char*) malloc(32 * sizeof(char));
    *LastModification = (char*) malloc(32 * sizeof(char));
    *LastChange = (char*) malloc(32 * sizeof(char));
    *LastAccess = (char*) malloc(32 * sizeof(char));

    STANDARD_INFORMATION* StandardInformation = (STANDARD_INFORMATION*) ((char *) StandardInformationAttribute + StandardInformationAttribute->Form.Resident.ValueOffset);

    SYSTEMTIME stUTC;
    FileTimeToSystemTime((FILETIME*) &StandardInformation->CreationTime, &stUTC);
    sprintf(*Creation, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformation->LastModificationTime, &stUTC);
    sprintf(*LastModification, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformation->LastChangeTime, &stUTC);
    sprintf(*LastChange, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

    FileTimeToSystemTime((FILETIME*) &StandardInformation->LastAccessTime, &stUTC);
    sprintf(*LastAccess, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
}

void ReadFileNameAttributeValueFields(ATTRIBUTE_RECORD_HEADER* FileNameAttribute, wchar_t** Name){

    FILE_NAME* FileName = (FILE_NAME*) ((char*) FileNameAttribute + FileNameAttribute->Form.Resident.ValueOffset);

    *Name = (WCHAR*) malloc((FileName->FileNameLength + 1) * sizeof(WCHAR));

    wcsncpy(*Name, FileName->FileName, FileName->FileNameLength);
    wcsncpy(*Name + FileName->FileNameLength, L"\0", 1);

}

// MFT Traversal output functions

// TODO : This functions are almost the same, refactor them into one

void PrintSummaryFileRecordSegment(char* FileRecordSegment, char* Buffer, uint64_t BufferSize){

    FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader = (FILE_RECORD_SEGMENT_HEADER*) FileRecordSegment;
    ULONG AttributeOffset = FileRecordSegmentHeader->FirstAttributeOffset;

    printf("\n\r[+] FileRecordSegment: Entry %lld\r\n", (FileRecordSegment-Buffer)/FILE_RECORD_SEGMENT_SIZE);

    // Loop all File Attributes
    while (1) {
        ATTRIBUTE_RECORD_HEADER* AttrRecordHeader = (ATTRIBUTE_RECORD_HEADER*) ((char *) FileRecordSegment + AttributeOffset);

        PrintSummaryAttributeRecordHeader(AttrRecordHeader);

        if (AttrRecordHeader->TypeCode == $STANDARD_INFORMATION) {
            PrintSummaryStandardInformationAttributeValue((STANDARD_INFORMATION*) ((char *) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset));
        }
        if (AttrRecordHeader->TypeCode == $FILE_NAME) {
            
            FILE_NAME* FileNameAttributeValue = (FILE_NAME*) ((char*) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset);
            PrintSummaryFileNameAttributeValue(FileNameAttributeValue);
            PrintSummaryFilePath(FileNameAttributeValue, Buffer, BufferSize);
        }
        if (AttrRecordHeader->TypeCode == $END) break;
        if (AttrRecordHeader->TypeCode == $UNUSED) break;
        if ((USHORT) AttrRecordHeader->RecordLength == 0) break; // TODO: Properly fix this type casting hack

        // HACK: For some weird reason I have yet to undestand, this type casting is needed to make it work.
        // RecordLength is defined as ULONG, but if I don't cast it to USHORT sometimes resolves to another 
        // much bigger number, which causes the offset to point much further, breaking the whole thing.
        AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
    }
}

void PrintCSVFileRecordSegment(char* FileRecordSegment, char* Buffer, uint64_t BufferSize){

    FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader = (FILE_RECORD_SEGMENT_HEADER*) FileRecordSegment;
    ULONG AttributeOffset = FileRecordSegmentHeader->FirstAttributeOffset;

    // Get Standard Information
    ATTRIBUTE_RECORD_HEADER* StandardInformationAttribute = GetStandardInformationAttribute(FileRecordSegmentHeader);
    if (!StandardInformationAttribute) {
        // TODO: Handle this
        // Standard Information Attribute not found! Skipping this File Record Segment.
        return;
    }
    STANDARD_INFORMATION* StandardInformationAttributeValue = (STANDARD_INFORMATION*) ((char *) StandardInformationAttribute + StandardInformationAttribute->Form.Resident.ValueOffset);

    // Loop all File Name Attributes
    while (1) {
        ATTRIBUTE_RECORD_HEADER* AttrRecordHeader = (ATTRIBUTE_RECORD_HEADER*) ((char *) FileRecordSegment + AttributeOffset);

        if (AttrRecordHeader->TypeCode == $FILE_NAME) {
            
            FILE_NAME* FileNameAttributeValue = (FILE_NAME*) ((char*) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset);

            // Ignore DOS-only File Names

            if (!(FileNameAttributeValue->Flags & FILE_NAME_NTFS)) {
                AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
                continue;
            }

            // Print Path

            printf("%lld,", (FileRecordSegment-Buffer)/FILE_RECORD_SEGMENT_SIZE);
            PrintFilePath(FileNameAttributeValue, Buffer, BufferSize);

            // Prints Standard Information

            char CreationTime[32];
            char LastModificationTime[32];
            char LastChangeTime[32];
            char LastAccessTime[32];

            SYSTEMTIME stUTC;

            FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->CreationTime, &stUTC);
            sprintf(CreationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastModificationTime, &stUTC);
            sprintf(LastModificationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastChangeTime, &stUTC);
            sprintf(LastChangeTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            FileTimeToSystemTime((FILETIME*) &StandardInformationAttributeValue->LastAccessTime, &stUTC);
            sprintf(LastAccessTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            printf(",%s,%s,%s,%s", LastModificationTime, LastAccessTime, LastChangeTime, CreationTime);

            // Print File Name Information

            FileTimeToSystemTime((FILETIME*) &FileNameAttributeValue->Info.CreationTime, &stUTC);
            sprintf(CreationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            FileTimeToSystemTime((FILETIME*) &FileNameAttributeValue->Info.LastModificationTime, &stUTC);
            sprintf(LastModificationTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            FileTimeToSystemTime((FILETIME*) &FileNameAttributeValue->Info.LastChangeTime, &stUTC);
            sprintf(LastChangeTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            FileTimeToSystemTime((FILETIME*) &FileNameAttributeValue->Info.LastAccessTime, &stUTC);
            sprintf(LastAccessTime, "%02d/%02d/%d %02d:%02d:%02d+00:00", stUTC.wDay, stUTC.wMonth, stUTC.wYear, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);

            printf(",%s,%s,%s,%s", LastModificationTime, LastAccessTime, LastChangeTime, CreationTime);
            
            printf("\r\n");

        }

        if (AttrRecordHeader->TypeCode == $END) break;
        if (AttrRecordHeader->TypeCode == $UNUSED) break;
        if ((USHORT) AttrRecordHeader->RecordLength == 0) break; // TODO: Properly fix this type casting hack

        AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
    }
}

void PrintPathsFileRecordSegment(char* FileRecordSegment, char* Buffer, uint64_t BufferSize){

    FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader = (FILE_RECORD_SEGMENT_HEADER*) FileRecordSegment;
    ULONG AttributeOffset = FileRecordSegmentHeader->FirstAttributeOffset;

    // Loop all File Name Attributes
    while (1) {
        ATTRIBUTE_RECORD_HEADER* AttrRecordHeader = (ATTRIBUTE_RECORD_HEADER*) ((char *) FileRecordSegment + AttributeOffset);

        if (AttrRecordHeader->TypeCode == $FILE_NAME) {
            
            FILE_NAME* FileNameAttributeValue = (FILE_NAME*) ((char*) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset);

            // Ignore DOS-only File Names

            if (!(FileNameAttributeValue->Flags & FILE_NAME_NTFS)) {
                AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
                continue;
            }

            // Print Path

            PrintFilePath(FileNameAttributeValue, Buffer, BufferSize);
            printf("\r\n");
        }

        if (AttrRecordHeader->TypeCode == $END) break;
        if (AttrRecordHeader->TypeCode == $UNUSED) break;
        if ((USHORT) AttrRecordHeader->RecordLength == 0) break; // TODO: Properly fix this type casting hack

        AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
    }
}

void PrintVerboseFileRecordSegment(char* FileRecordSegment, char* Buffer, uint64_t BufferSize){

    FILE_RECORD_SEGMENT_HEADER* FileRecordSegmentHeader = (FILE_RECORD_SEGMENT_HEADER*) FileRecordSegment;
    ULONG AttributeOffset = FileRecordSegmentHeader->FirstAttributeOffset;

    printf("\n\r[+] FileRecordSegment: Entry %lld\r\n", (FileRecordSegment-Buffer)/FILE_RECORD_SEGMENT_SIZE);

    // Loop all File Attributes
    while (1) {
        ATTRIBUTE_RECORD_HEADER* AttrRecordHeader = (ATTRIBUTE_RECORD_HEADER*) ((char *) FileRecordSegment + AttributeOffset);

        PrintAttributeRecordHeader(AttrRecordHeader);

        if (AttrRecordHeader->TypeCode == $STANDARD_INFORMATION) {
            PrintStandardInformationAttributeValue((STANDARD_INFORMATION*) ((char *) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset));
        }
        if (AttrRecordHeader->TypeCode == $FILE_NAME) {
            
            FILE_NAME* FileNameAttributeValue = (FILE_NAME*) ((char*) AttrRecordHeader + AttrRecordHeader->Form.Resident.ValueOffset);
            PrintFileNameAttributeValue(FileNameAttributeValue);
        }
        if (AttrRecordHeader->TypeCode == $END) break;
        if (AttrRecordHeader->TypeCode == $UNUSED) break;
        if ((USHORT) AttrRecordHeader->RecordLength == 0) break; // TODO: Properly fix this type casting hack

        AttributeOffset += (USHORT) AttrRecordHeader->RecordLength; // TODO: Properly fix this type casting hack
    }
}

// Main

void PrintEntryModeWrapper(char* FileRecordSegment, char* Buffer, uint64_t BufferSize) {
    if(output_mode == MODE_CSV) PrintCSVFileRecordSegment(FileRecordSegment, Buffer, BufferSize);
    else if(output_mode == MODE_SUMMARY) PrintSummaryFileRecordSegment(FileRecordSegment, Buffer, BufferSize);
    else if(output_mode == MODE_PATHS) PrintPathsFileRecordSegment(FileRecordSegment, Buffer, BufferSize);
    else if(output_mode == MODE_VERBOSE) PrintVerboseFileRecordSegment(FileRecordSegment, Buffer, BufferSize);
};

void TraverseAllMFT(char* Buffer, uint64_t BufferSize) {
    char* FileRecordSegment;
    FileRecordSegment = Buffer;
    while (FileRecordSegment < Buffer + BufferSize) {
        PrintEntryModeWrapper(FileRecordSegment, Buffer, BufferSize);
        FileRecordSegment += FILE_RECORD_SEGMENT_SIZE;
    }
}

void TraversePartialMFT(char* Buffer, uint64_t BufferSize, int StartEntry, int EndEntry) {
    char* FileRecordSegment;
    FileRecordSegment = Buffer + (FILE_RECORD_SEGMENT_SIZE * StartEntry);
    while (FileRecordSegment < Buffer + BufferSize && StartEntry <= EndEntry) {
        PrintEntryModeWrapper(FileRecordSegment, Buffer, BufferSize);
        FileRecordSegment += FILE_RECORD_SEGMENT_SIZE;
        StartEntry++;
    }
}

void Usage(char* argv[]) {
    printf("Usage: %s [csv|summary|paths|verbose] <MFT_FILE> \r\n", argv[0]);
    printf("Try '%s --help' for more information.\r\n", argv[0]);
    exit(1);
}

void Help(char* argv[]) {
    printf("Usage: %s [csv|summary|paths|verbose] <MFT_FILE> \r\n\r\n\
    modes: \r\n\
          csv: Print MFT entries as CSV\r\n\
      summary: Print a summary for each MFT entry\r\n\
        paths: Print a list of paths for each MFT entry\r\n\
      verbose: Print MFT entries with verbose output (for debugging purposes)\r\n", argv[0]);
    exit(0);
}

int main(int argc, char* argv[]) {

    // Parse arguments

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0))
        Help(argv);

    if (argc != 3)
        Usage(argv);

    if (strcmp(argv[1], "csv") == 0) output_mode = MODE_CSV;
    else if (strcmp(argv[1], "summary") == 0) output_mode = MODE_SUMMARY;
    else if (strcmp(argv[1], "paths") == 0) output_mode = MODE_PATHS;
    else if (strcmp(argv[1], "verbose") == 0) output_mode = MODE_VERBOSE;
    else Usage(argv);

    // Open and Read file

    OFSTRUCT ofstruct = {0};

    HFILE HFile = OpenFile(argv[2], &ofstruct, OF_READ);
    if (!HFile) ErrorExit(L"OpenFile");
    // printf(" * File Handle (HFILE): %d\r\n", (int)HFile);

    uint32_t ReadBytes;
    uint64_t BufferSize = 0;

    BufferSize = GetFileSize(HFile, (DWORD*) &BufferSize);
    if (!HFile) ErrorExit(L"GetFileSize");
    // printf(" * File size: %lld\r\n", BufferSize);

    char* Buffer = (char*) malloc(BufferSize * sizeof(char));
    if (!Buffer) ErrorExit(L"malloc");

    BOOL Flag = ReadFile(HFile, Buffer, BufferSize, &ReadBytes, NULL);
    if (!Flag) ErrorExit(L"ReadFile");
    if (ReadBytes != BufferSize) ErrorExit(L"ReadFile (not fully read)");
    // printf(" * Bytes read: %d\r\n", ReadBytes);

    TraverseAllMFT(Buffer, BufferSize);
    // TraversePartialMFT(Buffer, BufferSize, 0, 10);

    free(Buffer);
    return 0;
}
