#/usr/bin/env python3
# Dependecies: python-magic (pip3 install python-magic)
# MacOS: libmagic (brew install libmagic)
# Windows: libmagic dll

import argparse
import sqlite3
import sys
import zipfile
import uuid
import plistlib
from datetime import datetime
from os.path import basename, dirname
from io import BytesIO
from struct import unpack
from binascii import hexlify
import magic
import click

#extra field struct formats
datefmt  = '<2sHB4I'
ownerfmt = '<2sH2BIBI'
inodefmt = '<2sHQL'
gkfmt    = '<2sH2B'


def get_file_type(data: bytes, db: sqlite3) -> tuple:
    """Return the RowIDs from MIME and file type tables of submitted bytes.  
    Previously unidentified types are first added to their respective tables."""
    
    c = db.cursor()
    
    # Determine MIME Type
    mime = magic.from_buffer(data, mime=True)

    # Check if MIME type already exists in mtypes table, else add
    c.execute('SELECT ID FROM mtypes WHERE ? = MIME;', (mime,))
    m = c.fetchone()
    if not m:
        c.execute('INSERT INTO mtypes (MIME) VALUES (?);', (mime,))
        c.execute('SELECT last_insert_rowid();')
        mrow = c.fetchone()[0]
    else:
        mrow = m[0]

    # Determine file type
    # Required a try/except clause because of python-magic error
    try:
        ftype = magic.from_buffer(data)

        # Check of file type already exists in ftypes table, else add
        c.execute('SELECT ID FROM ftypes where ? = Type;', (ftype,))
        f = c.fetchone()
        if not f:
            c.execute('INSERT INTO ftypes (type) values (?);', (ftype,))
            c.execute('SELECT last_insert_rowid();')
            frow = c.fetchone()[0]
        else:
            frow = f[0]
    except:
        frow = 'FILE MAGIC ERROR'

    return mrow, frow

def get_xattrs(extra: BytesIO, db: sqlite3, fileID: int ) -> int:

    xcount = unpack('<I', extra.read(4))[0]
    c = db.cursor()

    for i in range(xcount):
        length = unpack('<I', extra.read(4))[0]
        key, raw_value = extra.read(length).split(b'\x00', 1)
        key, value = key.decode(), None

        if isinstance(raw_value, int):
            value = raw_value
        elif "assetsd" in key and len(raw_value) == 2:
            value = unpack('<H', raw_value)[0]
        elif 'ANI' in key or 'clen' in key and len(raw_value) == 8:
            value = unpack('<Q', raw_value)[0]
        elif key in ('Install', 'LAD', 'LMD', 'Upgrade') and \
            len(raw_value) == 8:
            value = unpack('<d', raw_value)[0]
        elif key.endswith('szmodtime'):
            value = unpack('<d', raw_value)[0]
        elif key.endswith('SHA1'):
            value = hexlify(raw_value).decode()
        elif key.endswith('retired-reason'):
            value = raw_value.rstrip(b'\x00').decode()
        elif key.endswith('timeZoneOffset'):
            value = unpack('<i', raw_value)[0]
        elif key.endswith('date#PS'):
            value = unpack('<L', raw_value[:4])[0]
            value = datetime.fromtimestamp(value)
        elif key.endswith('UUID#PS') or key.endswith('assestd.UUID'):
            value = str(uuid.UUID(bytes=raw_value)).upper()
        elif raw_value.startswith(b'bplist'):
            value = str(plistlib.loads(raw_value))
        else:
            try:
                value = raw_value.decode()
            except:
                value = raw_value

        c.execute('''INSERT INTO xattrs (FileID, Key, Value, Raw) 
            VALUES (?,?,?,?);''', (fileID, key, value, raw_value))
    
    return xcount

def extract_metadata(z: zipfile.ZipFile, db: sqlite3, 
    ftype: bool = False, ) -> None:
    """Return a list of files/directories from a ZipInfo object created from a 
    Graykey "full_files" zip archive."""
    
    c = db.cursor()
    fileID = 0
    
    with click.progressbar(z.infolist()) as bar:
        for f in bar:
            fname   = basename(f.filename.rstrip('/'))
            path    = dirname(f.filename.rstrip('/'))
            fullpath = f.filename
            isdir   = int(f.is_dir())
            size    = f.file_size
            offset  = f.header_offset
            mime    = None

            if ftype:
                data = BytesIO(z.read(f))
                mime, ftype = get_file_type(data.read(2048), db)

            #create extra data IO object for parsing
            extra = BytesIO(f.extra)

            # extract data block elements
            dhdr, dsz, dflag, mtime, atime, ctime, btime = unpack(datefmt, 
                extra.read(21))

            # extract owner block elements
            ohdr, osz, over, uid_sz, uid, gid_sz, gid = unpack(ownerfmt, 
                extra.read(15))

            # extract inode block elements
            ihdr, isz, inode, devID = unpack(inodefmt, extra.read(16))

            # extract graykey block elements
            ghdr, gsz, gver, gflag = unpack(gkfmt, extra.read(6))

            # check extraction version for compatibility
            if gver != 1:
                raise ValueError(f'Unsupported Graykey version: {gver}')
            
            # set base values
            dp, xcount = None, 0
            if gflag & 1: 
                dp = unpack('<I', extra.read(4))[0]

            if gflag & 2:
                xcount = get_xattrs(extra, db, fileID)

            c.execute('''INSERT INTO files (ID, Name, Path, FullPath, isDir,
            Size, Mtime, Atime, Ctime, Btime, UID, GID, iNode, DevID, DP, 
            Xcount, Offset, MIME, Type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
            ?,?,?);''', (fileID, fname, path, fullpath, isdir, size, mtime, 
            atime, ctime, btime, uid, gid, inode, devID, dp, xcount, offset, 
            mime, ftype))

            if fileID % 10000 == 0:
                db.commit()
            fileID += 1

        db.commit()
        db.close()
        return 

def construct_db(db: str) -> sqlite3:
    """Build empty database 'db'."""

    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.executescript('''
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
        left join ftypes on files.Type = ftypes.ID;

    CREATE VIEW utc as 
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
        left join ftypes on files.Type = ftypes.ID;
    ''')
    conn.commit()
    return conn

def main():

    parser = argparse.ArgumentParser(description='Extract metadata from \
        Graykey full files extraction.', epilog='Offsets are shown to the \
        local file record in the zip file for validation purposes.')
    parser.add_argument('ZIP', help='The Graykey "*_full_files.zip" archive')
    parser.add_argument('DB', help='The output SQLite database')
    parser.add_argument('-t', '--type', action='store_true', 
        help='Determine file type (slow)')
    
    args  = parser.parse_args()
    zfile = args.ZIP
    db    = args.DB
    ftype = args.type

    # Test that zip argument is a valid file
    if not zipfile.is_zipfile(zfile):
        raise(TypeError, f'{zfile} is not a proper zip file\n')

    # Create the empty database
    db = construct_db(db)

    # create a ZipFile object 
    print(f'\nIngesting archive metadata: this may take a while...', end='')
    z = zipfile.ZipFile(zfile, 'r')
    print(' complete!')
    
    # extract metadata
    if ftype:
        print('Processing archive metadata and type files... this WILL take a while!')
    else:
        print('Processing archive metadata:')
    metadata = extract_metadata(z, db, ftype)

if __name__ == '__main__':
    main()
    sys.exit(0)