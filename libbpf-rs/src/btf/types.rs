//! Wrappers representing concrete btf types.

use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;

use super::BtfKind;
use super::BtfType;
use super::HasSize;
use super::ReferencesType;
use super::TypeId;
use std::ffi::CStr;
use std::fmt;
use std::fmt::Display;
use std::ops::Deref;

// Generate a btf type that doesn't have any fields, i.e. there is no data after the BtfType
// pointer.
macro_rules! gen_fieldless_concrete_type {
    ($name:ident $(with $trait:ident)?) => {
        #[allow(missing_docs)]
        #[derive(Debug)]
        pub struct $name<'btf> {
            source: BtfType<'btf>,
        }

        impl<'btf> TryFrom<BtfType<'btf>> for $name<'btf> {
            type Error = BtfType<'btf>;

            fn try_from(t: BtfType<'btf>) -> ::core::result::Result<Self, Self::Error> {
                if t.kind() == BtfKind::$name {
                    Ok($name { source: t })
                } else {
                    Err(t)
                }
            }
        }

        impl<'btf> ::std::ops::Deref for $name<'btf> {
            type Target = BtfType<'btf>;
            fn deref(&self) -> &Self::Target {
                &self.source
            }
        }

        $(
            impl super::sealed::Sealed for $name<'_> {}
            unsafe impl<'btf> $trait<'btf> for $name<'btf> {}
        )*
    };
}

// Generate a btf type that has at least one field, and as such, there is data following the
// btf_type pointer.
macro_rules! gen_concrete_type {
    ($libbpf_ty:ident as $name:ident $(with $trait:ident)?) => {
        #[allow(missing_docs)]
        #[derive(Debug)]
        pub struct $name<'btf> {
            source: BtfType<'btf>,
            ptr: &'btf libbpf_sys::$libbpf_ty,
        }

        impl<'btf> TryFrom<BtfType<'btf>> for $name<'btf> {
            type Error = BtfType<'btf>;

            fn try_from(t: BtfType<'btf>) -> ::core::result::Result<Self, Self::Error> {
                if t.kind() == BtfKind::$name {
                    let ptr = unsafe {
                        // SAFETY:
                        //
                        // It's in bounds to access the memory following this btf_type
                        // because we've checked the type
                        (t.ty as *const libbpf_sys::btf_type).offset(1)
                    };
                    let ptr = ptr.cast::<libbpf_sys::$libbpf_ty>();
                    Ok($name {
                        source: t,
                        // SAFETY:
                        //
                        // This pointer is aligned.
                        //      all fields of all struct have size and
                        //      alignment of u32, if t.ty was aligned, then this must be as well
                        //
                        // It's initialized
                        //      libbpf guarantees this since we've checked the type
                        //
                        // The lifetime will match the lifetime of the original t.ty reference.
                        ptr: unsafe { &*ptr },
                    })
                } else {
                    Err(t)
                }
            }
        }

        impl<'btf> ::std::ops::Deref for $name<'btf> {
            type Target = BtfType<'btf>;
            fn deref(&self) -> &Self::Target {
                &self.source
            }
        }

        $(
            impl super::sealed::Sealed for $name<'_> {}
            unsafe impl<'btf> $trait<'btf> for $name<'btf> {}
        )*
    };
}

macro_rules! gen_collection_members_concrete_type {
    (
        $libbpf_ty:ident as $name:ident $(with $trait:ident)?;

        $(#[$docs:meta])*
        struct $member_name:ident $(<$lt:lifetime>)? {
            $(
                $(#[$field_docs:meta])*
                pub $field:ident : $type:ty
            ),* $(,)?
        }

        |$btf:ident, $member:ident $(, $kind_flag:ident)?| $convert:expr
    ) => {
        impl<'btf> ::std::ops::Deref for $name<'btf> {
            type Target = BtfType<'btf>;
            fn deref(&self) -> &Self::Target {
                &self.source
            }
        }

        impl<'btf> $name<'btf> {
            /// Whether this type has no members
            pub fn is_empty(&self) -> bool {
                self.members.is_empty()
            }

            #[doc = ::core::concat!("How many members this [`", ::core::stringify!($name), "`] has")]
            pub fn len(&self) -> usize {
                self.members.len()
            }

            #[doc = ::core::concat!("Get a [`", ::core::stringify!($member_name), "`] at a given index")]
            /// # Errors
            ///
            /// This function returns [`None`] when the index is out of bounds.
            pub fn get(&self, index: usize) -> Option<$member_name$(<$lt>)*> {
                self.members.get(index).map(|m| self.c_to_rust_member(m))
            }

            #[doc = ::core::concat!("Returns an iterator over the [`", ::core::stringify!($member_name), "`]'s of the [`", ::core::stringify!($name), "`]")]
            pub fn iter(&'btf self) -> impl ExactSizeIterator<Item = $member_name$(<$lt>)*> + 'btf {
                self.members.iter().map(|m| self.c_to_rust_member(m))
            }

            fn c_to_rust_member(&self, member: &libbpf_sys::$libbpf_ty) -> $member_name$(<$lt>)* {
                let $btf = self.source.source;
                let $member = member;
                $(let $kind_flag = self.source.kind_flag();)*
                $convert
            }
        }

        $(#[$docs])*
        #[derive(Debug)]
        pub struct $member_name $(<$lt>)? {
            $(
                $(#[$field_docs])*
                pub $field: $type
            ),*
        }

        $(
            impl $crate::btf::sealed::Sealed for $name<'_> {}
            unsafe impl<'btf> $trait<'btf> for $name<'btf> {}
        )*
    };
}

macro_rules! gen_collection_concrete_type {
    (
        $libbpf_ty:ident as $name:ident $(with $trait:ident)?;

        $($rest:tt)+
    ) => {
        #[allow(missing_docs)]
        #[derive(Debug)]
        pub struct $name<'btf> {
            source: BtfType<'btf>,
            members: &'btf [libbpf_sys::$libbpf_ty],
        }

        impl<'btf> TryFrom<BtfType<'btf>> for $name<'btf> {
            type Error = BtfType<'btf>;

            fn try_from(t: BtfType<'btf>) -> ::core::result::Result<Self, Self::Error> {
                if t.kind() == BtfKind::$name {
                    let base_ptr = unsafe {
                        // SAFETY:
                        //
                        // It's in bounds to access the memory following this btf_type
                        // because we've checked the type
                        (t.ty as *const libbpf_sys::btf_type).offset(1)
                    };
                    let members = unsafe {
                        // SAFETY:
                        //
                        // This pointer is aligned.
                        //      all fields of all struct have size and
                        //      alignment of u32, if t.ty was aligned, then this must be as well
                        //
                        // It's initialized
                        //      libbpf guarantees this since we've checked the type
                        //
                        // The lifetime will match the lifetime of the original t.ty reference.
                        //
                        // The docs specify the length of the array is stored in vlen.
                        std::slice::from_raw_parts(base_ptr.cast(), t.vlen() as usize)
                    };
                    Ok(Self { source: t, members })
                } else {
                    Err(t)
                }
            }
        }

        gen_collection_members_concrete_type!{
            $libbpf_ty as $name $(with $trait)?;
            $($rest)*
        }
    };
}

/// The attributes of a member.
#[derive(Debug)]
pub enum MemberAttr {
    /// Member is a normal field.
    Normal {
        /// The offset of this member in the struct/union.
        offset: u32,
    },
    /// Member is a bitfield.
    BitField {
        /// The size of the bitfield.
        size: u8,
        /// The offset of the bitfield.
        offset: u32,
    },
}

impl MemberAttr {
    fn normal(offset: u32) -> Self {
        Self::Normal { offset }
    }

    fn bif_field(offset: u32) -> Self {
        Self::BitField {
            size: (offset >> 24) as u8,
            offset: offset & 0x00_ff_ff_ff,
        }
    }
}

#[derive(TryFromPrimitive, IntoPrimitive, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum Linkage {
    Static = 0,
    Global,
    Extern,
    Unknown,
}

impl Display for Linkage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Linkage::Static => "static",
                Linkage::Global => "global",
                Linkage::Extern => "extern",
                Linkage::Unknown => "(unknown)",
            }
        )
    }
}

// Void
gen_fieldless_concrete_type!(Void);

// Int

#[derive(Debug)]
#[allow(missing_docs)]
pub struct Int<'btf> {
    source: BtfType<'btf>,
    pub encoding: IntEncoding,
    pub offset: u8,
    pub bits: u8,
}

/// The kinds of ways a btf [Int] can be encoded.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum IntEncoding {
    Unsigned,
    Signed,
    Char,
    Bool,
}

impl<'btf> TryFrom<BtfType<'btf>> for Int<'btf> {
    type Error = BtfType<'btf>;

    fn try_from(t: BtfType<'btf>) -> std::result::Result<Self, Self::Error> {
        if t.kind() == BtfKind::Int {
            let int = {
                let base_ptr = t.ty as *const libbpf_sys::btf_type;
                let u32_ptr = unsafe {
                    // SAFETY:
                    //
                    // It's in bounds to access the memory following this btf_type
                    // because we've checked the type
                    base_ptr.offset(1).cast::<u32>()
                };
                unsafe {
                    // SAFETY:
                    //
                    // This pointer is aligned.
                    //      all fields of all struct have size and
                    //      alignment of u32, if t.ty was aligned, then this must be as well
                    //
                    // It's initialized
                    //      libbpf guarantees this since we've checked the type
                    //
                    // The lifetime will match the lifetime of the original t.ty reference.
                    *u32_ptr
                }
            };
            let encoding = match (int & 0x0f_00_00_00) >> 24 {
                0b1 => IntEncoding::Signed,
                0b10 => IntEncoding::Char,
                0b100 => IntEncoding::Bool,
                _ => IntEncoding::Unsigned,
            };
            Ok(Self {
                source: t,
                encoding,
                offset: ((int & 0x00_ff_00_00) >> 24) as u8,
                bits: (int & 0x00_00_00_ff) as u8,
            })
        } else {
            Err(t)
        }
    }
}

impl<'btf> Deref for Int<'btf> {
    type Target = BtfType<'btf>;
    fn deref(&self) -> &Self::Target {
        &self.source
    }
}

// SAFETY: Int has the .size field set.
impl super::sealed::Sealed for Int<'_> {}
unsafe impl<'btf> HasSize<'btf> for Int<'btf> {}

// Ptr
gen_fieldless_concrete_type!(Ptr with ReferencesType);

// Array
gen_concrete_type!(btf_array as Array);

impl Array<'_> {
    /// The type id of the stored type.
    pub fn ty(&self) -> TypeId {
        self.ptr.type_.into()
    }

    /// The type of index used.
    pub fn index_ty(&self) -> TypeId {
        self.ptr.index_type.into()
    }

    /// The capacity of the array.
    pub fn capacity(&self) -> usize {
        self.ptr.nelems as usize
    }
}

// Struct
gen_collection_concrete_type! {
    btf_member as Struct with HasSize;

    /// A member of a [Struct]
    struct StructMember<'btf> {
        /// The member's name
        pub name: Option<&'btf CStr>,
        /// The member's type
        pub ty: TypeId,
        /// The attributes of this member.
        pub attr: MemberAttr,
    }

    |btf, member, kflag| StructMember {
        name: btf.name_at(member.name_off),
        ty: member.type_.into(),
        attr: if kflag {
            MemberAttr::bif_field(member.offset)
        } else {
            MemberAttr::normal(member.offset)
        },
    }
}

// Union
gen_collection_concrete_type! {
    btf_member as Union with HasSize;

    /// A member of an [Union]
    struct UnionMember<'btf> {
        /// The member's name
        pub name: Option<&'btf CStr>,
        /// The member's type
        pub ty: TypeId,
        /// The attributes of this member.
        pub attr: MemberAttr,
    }

    |btf, member, kflag| UnionMember {
        name: btf.name_at(member.name_off),
        ty: member.type_.into(),
        attr: if kflag {
            MemberAttr::bif_field(member.offset)
        } else {
            MemberAttr::normal(member.offset)
        },
    }
}

/// Sometimes it's not usefull to distinguish structs from unions, in that case, one can use this
/// type to inspect any of them.
#[derive(Debug)]
pub struct Composite<'btf> {
    source: BtfType<'btf>,
    /// Whether this type is a struct.
    pub is_struct: bool,
    members: &'btf [libbpf_sys::btf_member],
}

impl<'btf> From<Struct<'btf>> for Composite<'btf> {
    fn from(s: Struct<'btf>) -> Self {
        Self {
            source: s.source,
            is_struct: true,
            members: s.members,
        }
    }
}

impl<'btf> From<Union<'btf>> for Composite<'btf> {
    fn from(s: Union<'btf>) -> Self {
        Self {
            source: s.source,
            is_struct: false,
            members: s.members,
        }
    }
}

impl<'btf> TryFrom<BtfType<'btf>> for Composite<'btf> {
    type Error = BtfType<'btf>;

    fn try_from(t: BtfType<'btf>) -> Result<Self, Self::Error> {
        Struct::try_from(t)
            .map(Self::from)
            .or_else(|_| Union::try_from(t).map(Self::from))
    }
}

impl<'btf> TryFrom<Composite<'btf>> for Struct<'btf> {
    type Error = Composite<'btf>;

    fn try_from(value: Composite<'btf>) -> Result<Self, Self::Error> {
        if value.is_struct {
            Ok(Self {
                source: value.source,
                members: value.members,
            })
        } else {
            Err(value)
        }
    }
}

impl<'btf> TryFrom<Composite<'btf>> for Union<'btf> {
    type Error = Composite<'btf>;

    fn try_from(value: Composite<'btf>) -> Result<Self, Self::Error> {
        if !value.is_struct {
            Ok(Self {
                source: value.source,
                members: value.members,
            })
        } else {
            Err(value)
        }
    }
}

// Composite
gen_collection_members_concrete_type! {
    btf_member as Composite with HasSize;

    /// A member of a [Struct]
    struct CompositeMember<'btf> {
        /// The member's name
        pub name: Option<&'btf CStr>,
        /// The member's type
        pub ty: TypeId,
        /// If this member is a bifield, these are it's attributes.
        pub attr: MemberAttr
    }

    |btf, member, kflag| CompositeMember {
        name: btf.name_at(member.name_off),
        ty: member.type_.into(),
        attr: if kflag {
            MemberAttr::bif_field(member.offset)
        } else {
            MemberAttr::normal(member.offset)
        },
    }
}

// Enum
gen_collection_concrete_type! {
    btf_enum as Enum with HasSize;

    /// A member of an [Enum]
    struct EnumMember<'btf> {
        /// The name of this enum variant.
        pub name: Option<&'btf CStr>,
        /// The numeric value of this enum variant.
        pub value: i32,
    }

    |btf, member| EnumMember {
        name: btf.name_at(member.name_off),
        value: member.val,
    }
}

// Fwd
gen_fieldless_concrete_type!(Fwd);

impl Fwd<'_> {
    #[allow(missing_docs)]
    pub fn kind(&self) -> FwdKind {
        if self.source.kind_flag() {
            FwdKind::Union
        } else {
            FwdKind::Struct
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
#[allow(missing_docs)]
pub enum FwdKind {
    Struct,
    Union,
}

// Typedef
gen_fieldless_concrete_type!(Typedef with ReferencesType);

// Volatile
gen_fieldless_concrete_type!(Volatile with ReferencesType);

// Const
gen_fieldless_concrete_type!(Const with ReferencesType);

// Restrict
gen_fieldless_concrete_type!(Restrict with ReferencesType);

// Func
gen_fieldless_concrete_type!(Func with ReferencesType);

impl Func<'_> {
    /// This function's linkage.
    pub fn linkage(&self) -> Linkage {
        self.source.vlen().try_into().unwrap_or(Linkage::Unknown)
    }
}

// FuncProto
gen_collection_concrete_type! {
    btf_param as FuncProto with ReferencesType;

    /// A parameter of a [FuncProto].
    struct FuncProtoParam<'btf> {
        /// The parameter's name
        pub name: Option<&'btf CStr>,
        /// The parameter's type
        pub ty: TypeId,
    }

    |btf, member| FuncProtoParam {
        name: btf.name_at(member.name_off),
        ty: member.type_.into()
    }
}

// Var
gen_concrete_type!(btf_var as Var with ReferencesType);

impl Var<'_> {
    /// The kind of linkage this variable has.
    pub fn linkage(&self) -> Linkage {
        self.ptr.linkage.try_into().unwrap_or(Linkage::Unknown)
    }
}

// DataSec
gen_collection_concrete_type! {
    btf_var_secinfo as DataSec with HasSize;

    /// Describes the btf var in a section.
    ///
    /// See [`DataSec`].
    struct VarSecInfo {
        /// The type id of the var
        pub ty: TypeId,
        /// The offset in the section
        pub offset: u32,
        /// The size of the type.
        pub size: usize,
    }

    |_btf, member| VarSecInfo {
        ty: member.type_.into(),
        offset: member.offset,
        size: member.size as usize
    }
}

// Float
gen_fieldless_concrete_type!(Float with HasSize);

// DeclTag
gen_concrete_type!(btf_decl_tag as DeclTag with ReferencesType);

impl DeclTag<'_> {
    /// The component index is present only when the tag points to a struct/union member or a
    /// function argument.
    /// And component_idx indicates which member or argument, this decl tag refers to.
    pub fn component_index(&self) -> Option<u32> {
        self.ptr.component_idx.try_into().ok()
    }
}

// TypeTag
gen_fieldless_concrete_type!(TypeTag with ReferencesType);

// Enum64
gen_collection_concrete_type! {
    btf_enum64 as Enum64 with HasSize;

    /// A member of an [Enum64].
    struct Enum64Member<'btf> {
        /// The name of this enum variant.
        pub name: Option<&'btf CStr>,
        /// The numeric value of this enum variant.
        pub value: u64,
    }

    |btf, member| Enum64Member {
        name: btf.name_at(member.name_off),
        value: {
            let hi: u64 = member.val_hi32.into();
            let lo: u64 = member.val_lo32.into();
            hi << 32 | lo
        },
    }
}
