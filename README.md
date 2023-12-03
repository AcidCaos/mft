# MFT Parser
A simple Master File Table (MFT) parser from an NTFS volume.

# Usage

Usage: `mft [csv|summary|paths|verbose] <MFT_FILE>`

## Modes

```
          csv: Print MFT entries as CSV
      summary: Print a summary for each MFT entry
        paths: Print a list of paths for each MFT entry
      verbose: Print MFT entries with verbose output (for debugging purposes)
```

# Build

Compile using [MSVC compiler](https://learn.microsoft.com/en-us/cpp/build/reference/compiler-command-line-syntax): `CL mft.c /Fe"mft.exe"`
