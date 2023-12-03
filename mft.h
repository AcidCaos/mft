#ifndef _NTFS_
#define _NTFS_

#define FILE_RECORD_SEGMENT_SIZE (1024)

// https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table
// https://learn.microsoft.com/en-us/windows/win32/devnotes/master-file-table
// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc781134(v=ws.10)#mft-and-metadata-files

/*

On an NTFS volume, the MFT is a relational database that consists of rows of file records and columns of file attributes.
It contains at least one entry for every file on an NTFS volume, including the MFT itself.
The MFT stores the information required to retrieve files from the NTFS partition.

Because the MFT stores information about itself, NTFS reserves the first 16 records of the MFT for metadata
files (approximately 16 KB), which are used to describe the MFT.
Metadata files that begin with a dollar sign ($) are described in the table Metadata Files Stored in the MFT.
The remaining records of the MFT contain the file and folder records for each file and folder on the volume.

*/

#define SEQUENCE_NUMBER_STRIDE (512)

// Represents the multisector header.
// https://learn.microsoft.com/en-us/windows/win32/devnotes/multi-sector-header

typedef struct _MULTI_SECTOR_HEADER {
  UCHAR  Signature[4];
  USHORT UpdateSequenceArrayOffset;
  USHORT UpdateSequenceArraySize;
} MULTI_SECTOR_HEADER, *PMULTI_SECTOR_HEADER;

// This array must be present at the offset described above.

typedef USHORT UPDATE_SEQUENCE_NUMBER, *PUPDATE_SEQUENCE_NUMBER;
typedef UPDATE_SEQUENCE_NUMBER UPDATE_SEQUENCE_ARRAY[1];
typedef UPDATE_SEQUENCE_ARRAY *PUPDATE_SEQUENCE_ARRAY;

// Represents an address in the master file table (MFT).
// The address is tagged with a circularly reused sequence number that is set at the time the MFT segment reference was valid.
// https://learn.microsoft.com/en-us/windows/win32/devnotes/mft-segment-reference

typedef struct _MFT_SEGMENT_REFERENCE {
  ULONG  SegmentNumberLowPart;
  USHORT SegmentNumberHighPart;
  USHORT SequenceNumber;
} MFT_SEGMENT_REFERENCE, *PMFT_SEGMENT_REFERENCE;

typedef MFT_SEGMENT_REFERENCE FILE_REFERENCE, *PFILE_REFERENCE;

// Represents the file record segment. This is the header for each file record segment in the master file table (MFT).
// https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header

typedef struct _FILE_RECORD_SEGMENT_HEADER {
  MULTI_SECTOR_HEADER   MultiSectorHeader;
  ULONGLONG             Lsn;
  USHORT                SequenceNumber;
  USHORT                ReferenceCount;
  USHORT                FirstAttributeOffset;
  USHORT                Flags; // FILE_xxx flags
  ULONG                 FirstFreeByte;
  ULONG                 BytesAvailable;
  FILE_REFERENCE        BaseFileRecordSegment;
  USHORT                NextAttributeInstance;
  UPDATE_SEQUENCE_ARRAY UpdateSequenceArray;
} FILE_RECORD_SEGMENT_HEADER, *PFILE_RECORD_SEGMENT_HEADER;

// FILE_xxx flags

#define FILE_RECORD_SEGMENT_IN_USE   (0x0001)
#define FILE_FILE_NAME_INDEX_PRESENT (0x0002)

// Attribute Type Code

typedef ULONG ATTRIBUTE_TYPE_CODE;

#define $UNUSED                       (0x00)
#define $STANDARD_INFORMATION         (0x10)
#define $ATTRIBUTE_LIST               (0x20)
#define $FILE_NAME                    (0x30)
#define $OBJECT_ID                    (0x40)
#define $SECURITY_DESCRIPTOR          (0x50)
#define $VOLUME_NAME                  (0x60)
#define $VOLUME_INFORMATION           (0x70)
#define $DATA                         (0x80)
#define $INDEX_ROOT                   (0x90)
#define $INDEX_ALLOCATION             (0xA0)
#define $BITMAP                       (0xB0)
#define $SYMBOLIC_LINK                (0xC0)
#define $EA_INFORMATION               (0xD0)
#define $EA                           (0xE0)
#define $PROPERTY_SET                 (0xF0)
#define $FIRST_USER_DEFINED_ATTRIBUTE (0x100)
#define $END                          (0xFFFFFFFF)

// Represents an entry in the attribute list.
// https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry

typedef struct _ATTRIBUTE_LIST_ENTRY {
  ATTRIBUTE_TYPE_CODE   AttributeTypeCode;
  USHORT                RecordLength;
  UCHAR                 AttributeNameLength;
  UCHAR                 AttributeNameOffset;
  LONGLONG              LowestVcn;
  MFT_SEGMENT_REFERENCE SegmentReference;
  USHORT                Reserved;
  WCHAR                 AttributeName[1];
} ATTRIBUTE_LIST_ENTRY, *PATTRIBUTE_LIST_ENTRY;

// Represents an attribute record.
// https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header

typedef struct _ATTRIBUTE_RECORD_HEADER {
  ATTRIBUTE_TYPE_CODE TypeCode;
  ULONG               RecordLength;
  UCHAR               FormCode;
  UCHAR               NameLength;
  USHORT              NameOffset;
  USHORT              Flags; // ATTRIBUTE_xxx flags
  USHORT              Instance;
  union {
    struct {
      ULONG  ValueLength;
      USHORT ValueOffset;
      UCHAR  ResidentFlags; // RESIDENT_FORM_xxx Flags
      UCHAR  Reserved;
    } Resident;
    struct {
      LONGLONG LowestVcn;
      LONGLONG HighestVcn;
      USHORT   MappingPairsOffset;
      UCHAR    CompressionUnit;
      UCHAR    Reserved[5];
      LONGLONG AllocatedLength;
      LONGLONG FileSize;
      LONGLONG ValidDataLength;
      LONGLONG TotalAllocated;
    } Nonresident;
  } Form;
} ATTRIBUTE_RECORD_HEADER, *PATTRIBUTE_RECORD_HEADER;

// ATTRIBUTE_xxx flags

#define ATTRIBUTE_FLAG_COMPRESSION_MASK (0x00FF)
#define ATTRIBUTE_FLAG_SPARSE           (0x8000)
#define ATTRIBUTE_FLAG_ENCRYPTED        (0x4000)

// RESIDENT_FORM_xxx flags

#define RESIDENT_FORM_INDEXED (0x01)

// Attribute Form Codes

#define RESIDENT_FORM    (0x00)
#define NONRESIDENT_FORM (0x01)

// Represents the standard information attribute. This attribute is present in every base file record and must be resident.
// https://learn.microsoft.com/en-us/windows/win32/devnotes/standard-information

typedef struct _STANDARD_INFORMATION {
  LONGLONG CreationTime;
  LONGLONG LastModificationTime;
  LONGLONG LastChangeTime;
  LONGLONG LastAccessTime;
  ULONG FileAttributes;
  ULONG MaximumVersions;
  ULONG VersionNumber;
  ULONG ClassId;
  ULONG OwnerId;
  ULONG SecurityId;
  ULONGLONG QuotaCharged;
  ULONGLONG Usn;
  ULONG Reserved;
} STANDARD_INFORMATION, *PSTANDARD_INFORMATION;

// Represents the duplicated information on the file name attribute.

typedef struct _DUPLICATED_INFORMATION {
  LONGLONG CreationTime;
  LONGLONG LastModificationTime;
  LONGLONG LastChangeTime;
  LONGLONG LastAccessTime;
  LONGLONG AllocatedLength;
  LONGLONG FileSize;
  ULONG FileAttributes;
  USHORT PackedEaSize;
  USHORT Reserved;
} DUPLICATED_INFORMATION, *PDUPLICATED_INFORMATION;

// Represents a file name attribute. A file has one file name attribute for every directory it is entered into.
// https://learn.microsoft.com/en-us/windows/win32/devnotes/file-name

typedef struct _FILE_NAME {
  FILE_REFERENCE         ParentDirectory;
  DUPLICATED_INFORMATION Info;
  UCHAR                  FileNameLength;
  UCHAR                  Flags; // FILE_NAME_xxx flags
  WCHAR                  FileName[1];
} FILE_NAME, *PFILE_NAME;

// FILE_NAME_xxx flags

#define FILE_NAME_NTFS (0x01)
#define FILE_NAME_DOS  (0x02)

#endif //  _NTFS_
