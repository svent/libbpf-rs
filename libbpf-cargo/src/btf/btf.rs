use std::cmp::{max, min};
use std::convert::TryFrom;
use std::ffi::CStr;
use std::mem::size_of;

use anyhow::{anyhow, bail, ensure, Result};
use object::{read::File, BinaryFormat, Object, ObjectSection};
use scroll::Pread;

use crate::btf::c_types::*;
use crate::btf::*;

pub struct Btf<'a> {
    endian: scroll::Endian,
    types: Vec<BtfType<'a>>,
    ptr_size: u32,
    string_table: &'a [u8],
}

impl<'a> Btf<'a> {
    pub fn new(object_file: &'a [u8]) -> Result<Self> {
        let elf = File::parse(object_file)?;
        ensure!(elf.format() == BinaryFormat::Elf, "Object file not ELF");

        let endian = if elf.is_little_endian() {
            scroll::LE
        } else {
            scroll::BE
        };

        let btf_section = elf
            .section_by_name(BTF_ELF_SEC)
            .ok_or_else(|| anyhow!("No .BTF section found"))?;
        let data = btf_section.data()?;

        // Read section header
        let hdr = data.pread_with::<btf_header>(0, endian)?;
        ensure!(hdr.magic == BTF_MAGIC, "Invalid BTF magic");
        ensure!(
            hdr.version == BTF_VERSION,
            "Unsupported BTF version: {}",
            hdr.version
        );

        // String table
        let str_off = (hdr.hdr_len + hdr.str_off) as usize;
        let str_end = str_off + (hdr.str_len as usize);
        ensure!(str_end <= data.len(), "String table out of bounds");
        let str_data = &data[str_off..str_end];

        // Type table
        let type_off = (hdr.hdr_len + hdr.type_off) as usize;
        let type_end = type_off + (hdr.type_len as usize);
        ensure!(type_end <= data.len(), "Type table out of bounds");
        let type_data = &data[type_off..type_end];

        let mut btf = Btf::<'a> {
            endian: endian,
            types: Vec::new(),
            ptr_size: if elf.is_64() { 8 } else { 4 },
            string_table: str_data,
        };

        // Load all types
        let mut off: usize = 0;
        while off < hdr.type_len as usize {
            let t = btf.load_type(&type_data[off..])?;
            off += Btf::type_size(&t);
            btf.types.push(t);
        }

        Ok(btf)
    }

    pub fn types(&self) -> &[BtfType<'a>] {
        &self.types
    }

    pub fn type_by_id(&self, type_id: u32) -> Option<&BtfType> {
        if (type_id as usize) < self.types.len() {
            Some(&self.types[type_id as usize])
        } else {
            None
        }
    }

    pub fn size_of(&self, type_id: u32) -> Option<u32> {
        if let Some(t) = self.type_by_id(type_id) {
            Some(match t {
                BtfType::Void => 0,
                BtfType::Int(t) => ((t.bits + 7) / 8).into(),
                BtfType::Volatile(t) => return self.size_of(t.type_id),
                BtfType::Const(t) => return self.size_of(t.type_id),
                BtfType::Restrict(t) => return self.size_of(t.type_id),
                BtfType::Ptr(_) => self.ptr_size,
                BtfType::Array(t) => match self.size_of(t.val_type_id) {
                    Some(s) => t.nelems * s,
                    None => return None,
                },
                BtfType::FuncProto(_) => 0,
                BtfType::Struct(t) => t.size,
                BtfType::Union(t) => t.size,
                BtfType::Enum(t) => t.size,
                BtfType::Fwd(_) => 0,
                BtfType::Typedef(t) => return self.size_of(t.type_id),
                BtfType::Func(_) => 0,
                BtfType::Var(_) => 0,
                BtfType::Datasec(t) => t.size,
            })
        } else {
            None
        }
    }

    pub fn align_of(&self, type_id: u32) -> Option<u32> {
        if let Some(t) = self.type_by_id(type_id) {
            Some(match t {
                BtfType::Void => 0,
                BtfType::Int(t) => min(self.ptr_size, ((t.bits + 7) / 8).into()),
                BtfType::Volatile(t) => return self.align_of(t.type_id),
                BtfType::Const(t) => return self.align_of(t.type_id),
                BtfType::Restrict(t) => return self.align_of(t.type_id),
                BtfType::Ptr(_) => self.ptr_size,
                BtfType::Array(t) => return self.align_of(t.val_type_id),
                BtfType::FuncProto(_) => 0,
                BtfType::Struct(t) | BtfType::Union(t) => {
                    let mut align = 1;
                    for m in &t.members {
                        if let Some(a) = self.align_of(m.type_id) {
                            align = max(align, a);
                        } else {
                            return None;
                        }
                    }

                    align
                }
                BtfType::Enum(t) => min(self.ptr_size, t.size),
                BtfType::Fwd(_) => 0,
                BtfType::Typedef(t) => return self.align_of(t.type_id),
                BtfType::Func(_) => 0,
                BtfType::Var(_) => 0,
                BtfType::Datasec(_) => 0,
            })
        } else {
            None
        }
    }

    pub fn skip_mods(&self, mut type_id: u32) -> Option<u32> {
        loop {
            if let Some(t) = self.type_by_id(type_id) {
                match t {
                    BtfType::Volatile(t) => type_id = t.type_id,
                    BtfType::Const(t) => type_id = t.type_id,
                    BtfType::Restrict(t) => type_id = t.type_id,
                    _ => return Some(type_id),
                };
            } else {
                return None;
            }
        }
    }

    pub fn skip_mods_and_typedefs(&self, mut type_id: u32) -> Option<u32> {
        loop {
            if let Some(t) = self.type_by_id(type_id) {
                match t {
                    BtfType::Volatile(t) => type_id = t.type_id,
                    BtfType::Const(t) => type_id = t.type_id,
                    BtfType::Restrict(t) => type_id = t.type_id,
                    BtfType::Typedef(t) => type_id = t.type_id,
                    _ => return Some(type_id),
                };
            } else {
                return None;
            }
        }
    }

    fn load_type(&self, data: &'a [u8]) -> Result<BtfType<'a>> {
        let t = data.pread_with::<btf_type>(0, self.endian)?;
        let extra = &data[size_of::<btf_type>()..];
        let kind = (t.info >> 24) & 0xf;

        match BtfKind::try_from(kind)? {
            BtfKind::Void => {
                let _ = BtfType::Void; // Silence unused variant warning
                bail!("Cannot load Void type");
            }
            BtfKind::Int => self.load_int(&t, extra),
            BtfKind::Ptr => Ok(BtfType::Ptr(BtfPtr {
                pointee_type: t.type_id,
            })),
            BtfKind::Array => self.load_array(extra),
            BtfKind::Struct => self.load_struct(&t, extra),
            BtfKind::Union => self.load_union(&t, extra),
            BtfKind::Enum => self.load_enum(&t, extra),
            BtfKind::Fwd => self.load_fwd(&t),
            BtfKind::Typedef => Ok(BtfType::Typedef(BtfTypedef {
                name: self.get_btf_str(t.name_off as usize)?,
                type_id: t.type_id,
            })),
            BtfKind::Volatile => Ok(BtfType::Volatile(BtfVolatile { type_id: t.type_id })),
            BtfKind::Const => Ok(BtfType::Const(BtfConst { type_id: t.type_id })),
            BtfKind::Restrict => Ok(BtfType::Restrict(BtfRestrict { type_id: t.type_id })),
            BtfKind::Func => Ok(BtfType::Func(BtfFunc {
                name: self.get_btf_str(t.name_off as usize)?,
                type_id: t.type_id,
            })),
            BtfKind::FuncProto => self.load_func_proto(&t, extra),
            BtfKind::Var => self.load_var(&t, extra),
            BtfKind::Datasec => self.load_datasec(&t, extra),
        }
    }

    fn load_int(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let info = extra.pread_with::<u32>(0, self.endian)?;
        let enc: u8 = ((info >> 24) & 0xf) as u8;
        let off: u8 = ((info >> 16) & 0xff) as u8;
        let bits: u8 = (info & 0xff) as u8;
        Ok(BtfType::Int(BtfInt {
            name: self.get_btf_str(t.name_off as usize)?,
            bits: bits,
            offset: off,
            encoding: BtfIntEncoding::try_from(enc)?,
        }))
    }

    fn load_array(&self, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let info = extra.pread_with::<btf_array>(0, self.endian)?;
        Ok(BtfType::Array(BtfArray {
            nelems: info.nelems,
            index_type_id: info.idx_type_id,
            val_type_id: info.val_type_id,
        }))
    }

    fn load_struct(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        Ok(BtfType::Struct(BtfComposite {
            name: self.get_btf_str(t.name_off as usize)?,
            is_struct: true,
            size: t.type_id,
            members: self.load_members(t, extra)?,
        }))
    }

    fn load_union(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        Ok(BtfType::Union(BtfComposite {
            name: self.get_btf_str(t.name_off as usize)?,
            is_struct: false,
            size: t.type_id,
            members: self.load_members(t, extra)?,
        }))
    }

    fn load_members(&self, t: &btf_type, extra: &'a [u8]) -> Result<Vec<BtfMember<'a>>> {
        let mut res = Vec::new();
        let mut off: usize = 0;
        let bits = Self::get_kind(t.info);

        for _ in 0..Btf::get_vlen(t.info) {
            let m = extra.pread_with::<btf_member>(off, self.endian)?;
            res.push(BtfMember {
                name: self.get_btf_str(m.name_off as usize)?,
                type_id: m.type_id,
                bit_size: if bits { (m.offset >> 24) as u8 } else { 0 },
                bit_offset: if bits { m.offset & 0xffffff } else { m.offset },
            });

            off += size_of::<btf_member>();
        }

        Ok(res)
    }

    fn load_enum(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let mut vals = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let v = extra.pread_with::<btf_enum>(off, self.endian)?;
            vals.push(BtfEnumValue {
                name: self.get_btf_str(v.name_off as usize)?,
                value: v.val,
            });

            off += size_of::<btf_enum>();
        }

        Ok(BtfType::Enum(BtfEnum {
            name: self.get_btf_str(t.name_off as usize)?,
            size: t.type_id,
            values: vals,
        }))
    }

    fn load_fwd(&self, t: &btf_type) -> Result<BtfType<'a>> {
        Ok(BtfType::Fwd(BtfFwd {
            name: self.get_btf_str(t.name_off as usize)?,
            kind: if Self::get_kind(t.info) {
                BtfFwdKind::Union
            } else {
                BtfFwdKind::Struct
            },
        }))
    }

    fn load_func_proto(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let mut params = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let p = extra.pread_with::<btf_param>(off, self.endian)?;
            params.push(BtfFuncParam {
                name: self.get_btf_str(p.name_off as usize)?,
                type_id: p.type_id,
            });

            off += size_of::<btf_param>();
        }

        Ok(BtfType::FuncProto(BtfFuncProto {
            ret_type_id: t.type_id,
            params: params,
        }))
    }

    fn load_var(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let kind = extra.pread_with::<u32>(0, self.endian)?;
        Ok(BtfType::Var(BtfVar {
            name: self.get_btf_str(t.name_off as usize)?,
            type_id: t.type_id,
            linkage: BtfVarLinkage::try_from(kind)?,
        }))
    }

    fn load_datasec(&self, t: &btf_type, extra: &'a [u8]) -> Result<BtfType<'a>> {
        let mut vars = Vec::new();
        let mut off: usize = 0;

        for _ in 0..Btf::get_vlen(t.info) {
            let v = extra.pread_with::<btf_datasec_var>(off, self.endian)?;
            vars.push(BtfDatasecVar {
                type_id: v.type_id,
                offset: v.offset,
                size: v.size,
            });

            off += size_of::<btf_datasec_var>();
        }

        Ok(BtfType::Datasec(BtfDatasec {
            name: self.get_btf_str(t.name_off as usize)?,
            size: t.type_id,
            vars: vars,
        }))
    }

    /// Returns size of type on disk in .BTF section
    fn type_size(t: &BtfType) -> usize {
        let common = size_of::<btf_type>();
        match t {
            BtfType::Void => 0,
            BtfType::Ptr(_)
            | BtfType::Fwd(_)
            | BtfType::Typedef(_)
            | BtfType::Volatile(_)
            | BtfType::Const(_)
            | BtfType::Restrict(_)
            | BtfType::Func(_) => common,
            BtfType::Int(_) | BtfType::Var(_) => common + size_of::<u32>(),
            BtfType::Array(_) => common + size_of::<btf_array>(),
            BtfType::Struct(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Union(t) => common + t.members.len() * size_of::<btf_member>(),
            BtfType::Enum(t) => common + t.values.len() * size_of::<btf_enum>(),
            BtfType::FuncProto(t) => common + t.params.len() * size_of::<btf_param>(),
            BtfType::Datasec(t) => common + t.vars.len() * size_of::<btf_datasec_var>(),
        }
    }

    fn get_vlen(info: u32) -> u32 {
        info & 0xffff
    }

    fn get_kind(info: u32) -> bool {
        (info >> 31) == 1
    }

    fn get_btf_str(&self, offset: usize) -> Result<&'a str> {
        let c_str = unsafe { CStr::from_ptr(&self.string_table[offset] as *const u8 as *const i8) };
        Ok(c_str.to_str()?)
    }
}
