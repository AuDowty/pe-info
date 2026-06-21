pub struct Image {
    pub bytes: Vec<u8>,
    pub file_size: u64,
    pub is_64: bool,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
    pub sections: Vec<Section>,
}

pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub characteristics: u16,
}

pub struct OptionalHeader {
    pub image_base: u64,
    pub address_of_entry_point: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub data_directories: Vec<DataDirectory>,
}

#[derive(Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_address: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

pub struct Import {
    pub dll: String,
    pub functions: Vec<ImportFn>,
}

pub enum ImportFn {
    Named(String),
    Ordinal(u16),
}

pub struct Export {
    pub ordinal: u32,
    pub rva: u32,
    pub name: String,
}

const DOS_SIG: u16 = 0x5a4d;
const PE_SIG: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x10b;
const PE32P_MAGIC: u16 = 0x20b;

impl Image {
    pub fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        let file_size = bytes.len() as u64;
        let b = bytes.as_slice();

        if read_u16(b, 0)? != DOS_SIG {
            return Err("not a PE file (missing MZ signature)".into());
        }
        let e_lfanew = read_u32(b, 0x3c)? as usize;
        if read_u32(b, e_lfanew)? != PE_SIG {
            return Err("not a PE file (missing PE\\0\\0 signature)".into());
        }

        let fh_off = e_lfanew + 4;
        let machine = read_u16(b, fh_off)?;
        let number_of_sections = read_u16(b, fh_off + 2)?;
        let size_of_optional_header = read_u16(b, fh_off + 16)?;
        let characteristics = read_u16(b, fh_off + 18)?;

        let oh_off = fh_off + 20;
        let magic = read_u16(b, oh_off)?;
        let is_64 = match magic {
            PE32_MAGIC => false,
            PE32P_MAGIC => true,
            _ => return Err(format!("unknown OptionalHeader magic 0x{magic:x}")),
        };

        let address_of_entry_point = read_u32(b, oh_off + 16)?;
        let size_of_image = read_u32(b, oh_off + 56)?;
        let size_of_headers = read_u32(b, oh_off + 60)?;
        let subsystem = read_u16(b, oh_off + 68)?;
        let dll_characteristics = read_u16(b, oh_off + 70)?;

        let (image_base, num_dirs_off, data_dir_off) = if is_64 {
            (read_u64(b, oh_off + 24)?, oh_off + 108, oh_off + 112)
        } else {
            (read_u32(b, oh_off + 28)? as u64, oh_off + 92, oh_off + 96)
        };
        let num_dirs = read_u32(b, num_dirs_off)? as usize;

        let mut data_directories = Vec::with_capacity(num_dirs);
        for i in 0..num_dirs {
            let off = data_dir_off + i * 8;
            data_directories.push(DataDirectory {
                virtual_address: read_u32(b, off)?,
                size: read_u32(b, off + 4)?,
            });
        }

        let section_table_offset = oh_off + size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for i in 0..number_of_sections as usize {
            let off = section_table_offset + i * 40;
            let name_bytes = b
                .get(off..off + 8)
                .ok_or_else(|| format!("section name out of bounds at 0x{off:x}"))?;
            let end = name_bytes.iter().position(|&c| c == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
                virtual_size: read_u32(b, off + 8)?,
                virtual_address: read_u32(b, off + 12)?,
                raw_size: read_u32(b, off + 16)?,
                raw_address: read_u32(b, off + 20)?,
                characteristics: read_u32(b, off + 36)?,
            });
        }

        Ok(Image {
            bytes,
            file_size,
            is_64,
            file_header: FileHeader {
                machine,
                number_of_sections,
                characteristics,
            },
            optional_header: OptionalHeader {
                image_base,
                address_of_entry_point,
                size_of_image,
                size_of_headers,
                subsystem,
                dll_characteristics,
                data_directories,
            },
            sections,
        })
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            let span = s.raw_size.max(s.virtual_size);
            if rva >= s.virtual_address && rva < s.virtual_address.saturating_add(span) {
                return Some(s.raw_address as usize + (rva - s.virtual_address) as usize);
            }
        }
        None
    }

    pub fn imports(&self) -> Result<Vec<Import>, String> {
        let dir = self
            .optional_header
            .data_directories
            .get(1)
            .copied()
            .unwrap_or(DataDirectory { virtual_address: 0, size: 0 });
        if dir.virtual_address == 0 {
            return Ok(Vec::new());
        }
        let start = self
            .rva_to_offset(dir.virtual_address)
            .ok_or("imports: directory RVA -> offset failed")?;
        let b = self.bytes.as_slice();

        let mut out = Vec::new();
        let mut pos = start;
        loop {
            let original_first_thunk = read_u32(b, pos)?;
            let name_rva = read_u32(b, pos + 12)?;
            let first_thunk = read_u32(b, pos + 16)?;
            if name_rva == 0 && first_thunk == 0 {
                break;
            }
            pos += 20;

            let name_off = self
                .rva_to_offset(name_rva)
                .ok_or("import: dll name RVA -> offset failed")?;
            let dll = read_cstring(b, name_off);

            let lookup_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let mut lookup_off = self
                .rva_to_offset(lookup_rva)
                .ok_or("import: lookup table RVA -> offset failed")?;
            let mut functions = Vec::new();
            let stride = if self.is_64 { 8 } else { 4 };
            let ord_flag: u64 = if self.is_64 {
                0x8000_0000_0000_0000
            } else {
                0x8000_0000
            };
            loop {
                let entry: u64 = if self.is_64 {
                    read_u64(b, lookup_off)?
                } else {
                    read_u32(b, lookup_off)? as u64
                };
                if entry == 0 {
                    break;
                }
                if entry & ord_flag != 0 {
                    functions.push(ImportFn::Ordinal((entry & 0xffff) as u16));
                } else {
                    let n_off = self
                        .rva_to_offset(entry as u32)
                        .ok_or("import: name table entry -> offset failed")?;
                    functions.push(ImportFn::Named(read_cstring(b, n_off + 2)));
                }
                lookup_off += stride;
            }
            out.push(Import { dll, functions });
        }
        Ok(out)
    }

    pub fn exports(&self) -> Result<Vec<Export>, String> {
        let dir = self
            .optional_header
            .data_directories
            .first()
            .copied()
            .unwrap_or(DataDirectory { virtual_address: 0, size: 0 });
        if dir.virtual_address == 0 {
            return Ok(Vec::new());
        }
        let b = self.bytes.as_slice();
        let off = self
            .rva_to_offset(dir.virtual_address)
            .ok_or("exports: directory RVA -> offset failed")?;

        let base_ordinal = read_u32(b, off + 16)?;
        let n_funcs = read_u32(b, off + 20)? as usize;
        let n_names = read_u32(b, off + 24)? as usize;
        let funcs_rva = read_u32(b, off + 28)?;
        let names_rva = read_u32(b, off + 32)?;
        let ords_rva = read_u32(b, off + 36)?;

        let funcs_off = self
            .rva_to_offset(funcs_rva)
            .ok_or("exports: AddressOfFunctions -> offset failed")?;
        let mut named: Vec<(u16, String)> = Vec::with_capacity(n_names);
        if n_names > 0 {
            let names_off = self
                .rva_to_offset(names_rva)
                .ok_or("exports: AddressOfNames -> offset failed")?;
            let ords_off = self
                .rva_to_offset(ords_rva)
                .ok_or("exports: AddressOfNameOrdinals -> offset failed")?;
            for i in 0..n_names {
                let ord = read_u16(b, ords_off + i * 2)?;
                let name_rva = read_u32(b, names_off + i * 4)?;
                let n_off = self
                    .rva_to_offset(name_rva)
                    .ok_or("exports: name entry -> offset failed")?;
                named.push((ord, read_cstring(b, n_off)));
            }
        }

        let mut out = Vec::with_capacity(n_funcs);
        for i in 0..n_funcs {
            let fn_rva = read_u32(b, funcs_off + i * 4)?;
            if fn_rva == 0 {
                continue;
            }
            let name = named
                .iter()
                .find(|(o, _)| *o as usize == i)
                .map(|(_, n)| n.clone())
                .unwrap_or_default();
            out.push(Export {
                ordinal: base_ordinal + i as u32,
                rva: fn_rva,
                name,
            });
        }
        out.sort_by_key(|e| e.ordinal);
        Ok(out)
    }
}

fn read_u16(b: &[u8], off: usize) -> Result<u16, String> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("read u16 at 0x{off:x} out of bounds"))
}
fn read_u32(b: &[u8], off: usize) -> Result<u32, String> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("read u32 at 0x{off:x} out of bounds"))
}
fn read_u64(b: &[u8], off: usize) -> Result<u64, String> {
    b.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or_else(|| format!("read u64 at 0x{off:x} out of bounds"))
}
fn read_cstring(b: &[u8], off: usize) -> String {
    let tail = &b[off..];
    let end = tail.iter().position(|&c| c == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}
