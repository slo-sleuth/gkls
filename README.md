# GKLS

This project started as a simple script to list the contents of a Graykey .zip file after I determined that the Zip file contained four dates (modified, accessed, changed, and created, AKA, born), only three of which were displayed by the commercial tools at my disposal.  I soon discovered that the the [Zip file specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) allowed for an "extra field" in the local file headers for capturing third party data, and Grayshift, to their credit, was using the field for storage of more than just dates, but owner and group IDs, Inode number and device IDs, data protection level and extended attributes.

A simple file list didn't really leverage the extra field information eloquently, so I shifted output to SQLite.  I may add back in the simple CSV listing in
a future version for circumstances where this best meets the user's needs.

## Requirements

The gkls.py script requires two third party packages: `python-magic` for file typing and `click` for a progress bar.  File type detection takes significantly longer than basic file system metadata extraction because each file in the archive must be accessed.

## Usage

```
% python3 gkls.py -h
usage: gkls.py [-h] [-t] ZIP DB

Extract metadata from Graykey full files extraction.

positional arguments:
  ZIP         The Graykey "*_full_files.zip" archive
  DB          The output SQLite database (must not exist)

optional arguments:
  -h, --help  show this help message and exit
  -t, --type  Determine file type (slow)

The offset to the local file record in the original ZIP file is provided for research and validation purposes.
```

### SQLite Schema

The database can be named anything sensible to the user, but it must not already exist or the script will fail.  The following schema is in use:

```
CREATE TABLE files (
        ID INTEGER PRIMARY KEY,
        Name TEXT,
        Path TEXT,
        FullPath TEXT,
        isDir INTEGER,
        Size INTEGER,
        Mtime INTEGER,
        Atime INTEGER,
        Ctime INTEGER,
        Btime INTEGER,
        UID INTEGER,
        GID INTEGER,
        iNode INTEGER,
        DevID INTEGER,
        DP INTEGER,
        XCount INTEGER,
        MIME INTEGER,
        Type INTEGER,
        Offset INTEGER
    );

CREATE TABLE xattrs (
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        FileID INTEGER,
        Key TEXT,
        Value TEXT,
        Raw BLOB
    );

CREATE TABLE sqlite_sequence(name,seq);

CREATE TABLE mtypes(
        ID INTEGER PRIMARY KEY AUTOINCREMENT,
        MIME TEXT
    );

CREATE TABLE ftypes (
        ID INTEGER PRIMARY KEY,
        Type TEXT
    );

CREATE VIEW localtime as 
        select 
            files.ID,
            Name,
            Path,
            FullPath,
            isDir,
            Size,
            datetime(mtime, 'unixepoch', 'localtime') as Mtime,
            datetime(atime, 'unixepoch', 'localtime') as Atime,
            datetime(ctime, 'unixepoch', 'localtime') as Ctime,
            datetime(btime, 'unixepoch', 'localtime') as Btime,
            UID,
            GID,
            iNode,
            DevID as DeviceID,
            mtypes.MIME,
            ftypes.Type,
            Xcount as ExtraAttrs,
            'Offset' as ZipOffset,
            Key as XattrKey,
            Value as XattrValue,
            Raw
        from files 
        left join xattrs on files.ID = xattrs.FileID
        left join mtypes on files.MIME = mtypes.ID
        left join ftypes on files.Type = ftypes.ID

CREATE VIEW utc as 
        select 
            files.ID,
            Name,
            Path,
            FullPath,
            isDir,
            Size,
            datetime(mtime, 'unixepoch') as Mtime,
            datetime(atime, 'unixepoch') as Atime,
            datetime(ctime, 'unixepoch') as Ctime,
            datetime(btime, 'unixepoch') as Btime,
            UID,
            GID,
            iNode,
            DevID as DeviceID,
            mtypes.MIME,
            ftypes.Type,
            Xcount as ExtraAttrs,
            'Offset' as ZipOffset,
            Key as XattrKey,
            Value as XattrValue,
            Raw
        from files 
        left join xattrs on files.ID = xattrs.FileID
        left join mtypes on files.MIME = mtypes.ID
        left join ftypes on files.Type = ftypes.ID
    );
```

## Extra Field Specifications

There are four data blocks in the Zip file extra field.  The Zip file specifications require that each block start with a four byte header consisting of a two-byte header ID and a two-byte integer indicating the size of the data in the block (not inclusive of the header).  Block values are read little endian.

### Extended Timestamp Block

The time stamp block is modeled after and has the same header ID as the more ubiquitous UNIX extended timestamp block, but it includes a created or "birth" time not present in the UNIX block.

|Key|Size(b)|Description 
|---|---|--- 
|Block ID|2|0x5455 (ASCII "UT")
|Data size|2|0x0011 (17 bytes, remaining block size)
|Flags|1|info bits (not yet understood)
|Mtime|4|file content modification time (UINT32)
|Atime|4|file accessed time (UINT32)
|Ctime|4|file metadata changed time (UINT32)
|Btime|4|file creation (birth) time (UINT32)

The time stamps are UNIX epoch, i.e., seconds since 1970-01-01 00:00:00 -0000.

### Ownership Block

The file ownership block contains the file's user ID and group ID, both of which are represented in a Unix-like system as integers.

|Key|Size(b)|Description 
|---|---|--- 
|Block ID|2|0x7875 (fixed, ASCII "ux")
|Data size|2|0x000b (11 bytes, remaining block size)
|Version|1|block version
|UID size|1|UID size
|UID|Variable|User ID (Unsigned VARINT)
|GID size|1|GID size
|GID|Variable|Group ID (Unsigned VARINT)

### Inode / Device ID Block

This block holds the file index number (Inode) and the Device ID.  The Device ID is not the iPhone GUID, but instead is consistent with a file system ID (i.e., a different mount point).

|Key|Size(b)|Description 
|---|---|--- 
|Block ID|2|0x4e49 (fixed, ASCII "IN")
|Data size|2|0x000c (UINT16, 12 bytes, remaining data size)
|Inode|8|Variable (uint64)
|Device ID|4|Variable (UINT32)

### Data Protection / Extended Attributes Block

|Key|Size(b)|Description 
|---|---|--- 
|Block ID|2|0x4b47 (fixed, ASCII "GK")
|Data size|2|variable (unsigned VARINT, remaining data size)
|Version|1|block version (UINT8)
|Flag|1|Data protection level and extended attributes indicator (UINT8) 

Bitwise AND math operation indicates the presence of a Data Protection value and/or extended attributes.

If Flag & 1: *(True if Flag = 1 or 3)*

|Key|Size(b)|Description 
|---|---|--- 
Data Protection|4|Data protection level (UINT32)

If Flag & 2: *(True if Flag = 2 or 3)*
|Key|Size(b)|Description 
|---|---|--- 
|Count|4|Number of extended attributes (UINT32)

For each extended attribute:
|Key|Size(b)|Description 
|---|---|--- 
|Data Length|4|Length of data
|Attribute|Variable|Null separated key/value pair

Attribute keys are UTF-8 encoded strings, but attribute keys can be any binary value.  I have observed them to be integers, floats (most often Mac Absolute Time), strings, and binary plists.  

The glks.py script attempts to detect different values and interpret them.  I provides the original (labeled "raw" as well as the interpreted value for comparison.
