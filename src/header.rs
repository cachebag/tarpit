pub use crate::error::HeaderParseError;

pub struct HeaderUstar {
    name:       [u8; 100],              // offset: 0 
    mode:       [u8; 8],                // offset: 100
    uid:        [u8; 8],                // offset: 108
    gid:        [u8; 8],                // offset: 116
    size:       [u8; 12],               // offset: 124
    mtime:      [u8; 12],               // offset: 136
    chksum:     [u8; 8],                // offset: 148
    typeflag:   u8,                     // offset: 156
    linkname:   [u8; 100],              // offset: 157
    magic:      [u8; 6],                // offset: 257
    version:    [u8; 2],                // offset: 263
    uname:      [u8; 32],               // offset: 265
    gname:      [u8; 32],               // offset: 297
    devmajor:   [u8; 8],                // offset: 329
    devminor:   [u8; 8],                // offset: 337
    prefix:     [u8; 155],              // offset: 345
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TypeFlags {
    Regtype,
    Aregtype,
    Lnktype,
    Symtype,
    Chrtype,
    Blktype,
    Dirtype,
    Fifotype,
    Conttype,
}

impl HeaderUstar {

    pub fn from_bytes(block: &[u8; 512]) -> Result<Self, HeaderParseError> {

        // string, name
        let mut name = [0u8; 100]; 
        name.copy_from_slice(&block[0..100]);
        
        // octal, mode 
        let mut mode = [0u8; 8];
        mode.copy_from_slice(&block[100..108]);

        // octal, uid 
        let mut uid = [0u8; 8];
        uid.copy_from_slice(&block[108..116]);

        // octal, gid
        let mut gid = [0u8; 8];
        gid.copy_from_slice(&block[116..124]);

        // octal, size 
        let mut size = [0u8; 12];
        size.copy_from_slice(&block[124..136]);

        // octal, mtime
        let mut mtime = [0u8; 12];
        mtime.copy_from_slice(&block[136..148]);

        // octal, chksum 
        let mut chksum = [0u8; 8];
        chksum.copy_from_slice(&block[148..156]);

        // string, linkname 
        let mut linkname = [0u8; 100];
        linkname.copy_from_slice(&block[157..257]);
    
        // string, magic 
        let mut magic = [0u8; 6];
        magic.copy_from_slice(&block[257..263]);

        // oct, version
        let mut version = [0u8; 2];
        version.copy_from_slice(&block[263..265]);

        if &magic != b"ustar\0" {
            return Err(HeaderParseError::InvalidMagic)
        }

        if &version != b"00" {
            return Err(HeaderParseError::InvalidVersion)
        }

        // string, uname
        let mut uname = [0u8; 32];
        uname.copy_from_slice(&block[265..297]);

        // string, gname 
        let mut gname = [0u8; 32];
        gname.copy_from_slice(&block[297..329]);

        // oct, devmajor 
        let mut devmajor = [0u8; 8];
        devmajor.copy_from_slice(&block[329..337]);

        // oct, devminor 
        let mut devminor = [0u8; 8];
        devminor.copy_from_slice(&block[337..345]);
    
        // string, prefix
        let mut prefix = [0u8; 155];
        prefix.copy_from_slice(&block[345..500]);

        // padding - 500 - 511


        Ok(HeaderUstar {
            name,
            mode, 
            uid, 
            gid,
            size,
            mtime,
            chksum,
            typeflag: block[156],
            linkname,
            magic,
            version,
            uname,
            gname,
            devmajor,
            devminor,
            prefix,
        })
    }

    // helper to parse fields with octal values
    fn parse_octal(field_name: &'static str, bytes: &[u8]) -> Result<u64, HeaderParseError> {
        let field_str= std::str::from_utf8(bytes)
            .map_err(|_| HeaderParseError::InvalidUtf8)?;

        let trimmed = field_str.trim_matches(|c| c == '\0' || c == ' ');

        if trimmed.is_empty() {
            return Ok(0);
        }

        let value = u64::from_str_radix(trimmed, 8)
            .map_err(|_| HeaderParseError::InvalidOctal(field_name))?;

            Ok(value)
        }

    pub fn file_name(&self) -> Result<String, HeaderParseError> {
        let name = std::str::from_utf8(&self.name)
            .map_err(|_| HeaderParseError::InvalidUtf8)?
            .trim_end_matches('\0')
            .to_string(); 
        
        Ok(name)
    }

    pub fn file_mode(&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("mode", &self.mode)
    }

    pub fn file_uid(&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("uid", &self.uid)
    }

    pub fn file_gid(&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("gid", &self.gid)
    }

    pub fn file_size(&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("size", &self.size)
    }

    pub fn file_mtime(&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("mtime", &self.mtime)
    }

    pub fn file_chksum(&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("chksum", &self.chksum)
    }

    pub fn file_type(&self) -> Result<TypeFlags, HeaderParseError> {

        match self.typeflag {
            b'0'            => Ok(TypeFlags::Regtype),
            b'\0'           => Ok(TypeFlags::Aregtype),
            b'1'            => Ok(TypeFlags::Lnktype),
            b'2'            => Ok(TypeFlags::Symtype),
            b'3'            => Ok(TypeFlags::Chrtype),
            b'4'            => Ok(TypeFlags::Blktype),
            b'5'            => Ok(TypeFlags::Dirtype),
            b'6'            => Ok(TypeFlags::Fifotype),
            b'7'            => Ok(TypeFlags::Conttype),
            _               => Err(HeaderParseError::InvalidTypeflag(self.typeflag)),
        }
    }

    pub fn file_linkname(&self) -> Result<String, HeaderParseError> {
        let linkname = std::str::from_utf8(&self.linkname)
            .map_err(|_| HeaderParseError::InvalidUtf8)?
            .trim_end_matches('\0')
            .to_string();

        Ok(linkname)
    } 
    
    pub fn file_magic(&self) -> Result<String, HeaderParseError> {
        let magic  = std::str::from_utf8(&self.magic)
            .map_err(|_| HeaderParseError::InvalidMagic)?
            .trim_end_matches('\0')
            .to_string();

        Ok(magic)
    }
    
    pub fn file_version(&self) -> Result<String, HeaderParseError> {
        let version = std::str::from_utf8(&self.version)
            .map_err(|_| HeaderParseError::InvalidVersion)?
            .trim_end_matches('\0')
            .to_string();

        Ok(version)
    }

    pub fn file_uname(&self) -> Result<String, HeaderParseError> {
        let uname = std::str::from_utf8(&self.uname)
            .map_err(|_| HeaderParseError::InvalidUtf8)?
            .trim_end_matches('\0')
            .to_string();

        Ok(uname)
    }

    pub fn file_gname(&self) -> Result<String, HeaderParseError> {
        let gname = std::str::from_utf8(&self.gname)
            .map_err(|_| HeaderParseError::InvalidUtf8)?
            .trim_end_matches('\0')
            .to_string();

        Ok(gname)
    }

    pub fn file_devmajor (&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("devmajor", &self.devmajor)
    }

    pub fn file_devminor (&self) -> Result<u64, HeaderParseError> {
        HeaderUstar::parse_octal("devminor", &self.devminor)
    }

    pub fn file_prefix (&self) -> Result<String, HeaderParseError> {
        let prefix = std::str::from_utf8(&self.prefix)
            .map_err(|_| HeaderParseError::InvalidUtf8)?
            .trim_end_matches('\0')
            .to_string();

        Ok(prefix)
    }
}
