use num_enum::TryFromPrimitive;

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u32)]
pub enum BtfKind {
    Void = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    Datasec = 15,
}

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum BtfIntEncoding {
    None = 0,
    Signed = 1 << 0,
    Char = 1 << 1,
    Bool = 1 << 2,
}

#[derive(Debug)]
pub struct BtfInt<'a> {
    pub name: &'a str,
    pub bits: u8,
    pub offset: u8,
    pub encoding: BtfIntEncoding,
}

#[derive(Debug)]
pub struct BtfPtr {
    pub pointee_type: u32,
}

#[derive(Debug)]
pub struct BtfArray {
    pub nelems: u32,
    pub index_type_id: u32,
    pub val_type_id: u32,
}

#[derive(Debug)]
pub struct BtfMember<'a> {
    pub name: &'a str,
    pub type_id: u32,
    pub bit_offset: u32,
    pub bit_size: u8,
}

#[derive(Debug)]
pub struct BtfComposite<'a> {
    pub name: &'a str,
    pub is_struct: bool,
    pub size: u32,
    pub members: Vec<BtfMember<'a>>,
}

#[derive(Debug)]
pub struct BtfEnumValue<'a> {
    pub name: &'a str,
    pub value: i32,
}

#[derive(Debug)]
pub struct BtfEnum<'a> {
    pub name: &'a str,
    pub size: u32,
    pub values: Vec<BtfEnumValue<'a>>,
}

#[derive(Debug, Copy, Clone)]
pub enum BtfFwdKind {
    Struct,
    Union,
}

#[derive(Debug)]
pub struct BtfFwd<'a> {
    pub name: &'a str,
    pub kind: BtfFwdKind,
}

macro_rules! btf_modifier {
    ($name: ident) => {
        #[derive(Debug)]
        pub struct $name {
            pub type_id: u32,
        }
    };

    ($name: ident, $_has_name: expr) => {
        #[derive(Debug)]
        pub struct $name<'a> {
            pub name: &'a str,
            pub type_id: u32,
        }
    };
}

btf_modifier!(BtfTypedef, true);
btf_modifier!(BtfVolatile);
btf_modifier!(BtfConst);
btf_modifier!(BtfRestrict);
btf_modifier!(BtfFunc, true);

#[derive(Debug)]
pub struct BtfFuncParam<'a> {
    pub name: &'a str,
    pub type_id: u32,
}

#[derive(Debug)]
pub struct BtfFuncProto<'a> {
    pub ret_type_id: u32,
    pub params: Vec<BtfFuncParam<'a>>,
}

#[derive(Debug, Copy, Clone, TryFromPrimitive)]
#[repr(u32)]
pub enum BtfVarLinkage {
    Static = 0,
    GlobalAlloc = 1,
    GlobalExtern = 2,
}

#[derive(Debug)]
pub struct BtfVar<'a> {
    pub name: &'a str,
    pub type_id: u32,
    pub linkage: BtfVarLinkage,
}

#[derive(Debug)]
pub struct BtfDatasecVar {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct BtfDatasec<'a> {
    pub name: &'a str,
    pub size: u32,
    pub vars: Vec<BtfDatasecVar>,
}

pub enum BtfType<'a> {
    Void,
    Int(BtfInt<'a>),
    Ptr(BtfPtr),
    Array(BtfArray),
    Struct(BtfComposite<'a>),
    Union(BtfComposite<'a>),
    Enum(BtfEnum<'a>),
    Fwd(BtfFwd<'a>),
    Typedef(BtfTypedef<'a>),
    Volatile(BtfVolatile),
    Const(BtfConst),
    Restrict(BtfRestrict),
    Func(BtfFunc<'a>),
    FuncProto(BtfFuncProto<'a>),
    Var(BtfVar<'a>),
    Datasec(BtfDatasec<'a>),
}

impl<'a> BtfType<'a> {
    pub fn kind(&self) -> BtfKind {
        match self {
            BtfType::Void => BtfKind::Void,
            BtfType::Ptr(_) => BtfKind::Ptr,
            BtfType::Fwd(_) => BtfKind::Fwd,
            BtfType::Typedef(_) => BtfKind::Typedef,
            BtfType::Volatile(_) => BtfKind::Volatile,
            BtfType::Const(_) => BtfKind::Const,
            BtfType::Restrict(_) => BtfKind::Restrict,
            BtfType::Func(_) => BtfKind::Func,
            BtfType::Int(_) => BtfKind::Int,
            BtfType::Var(_) => BtfKind::Var,
            BtfType::Array(_) => BtfKind::Array,
            BtfType::Struct(_) => BtfKind::Struct,
            BtfType::Union(_) => BtfKind::Union,
            BtfType::Enum(_) => BtfKind::Enum,
            BtfType::FuncProto(_) => BtfKind::FuncProto,
            BtfType::Datasec(_) => BtfKind::Datasec,
        }
    }
}
