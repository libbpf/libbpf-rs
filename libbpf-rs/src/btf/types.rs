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
    (
        $(#[$docs:meta])*
        $name:ident $(with $trait:ident)?
    ) => {
        $(#[$docs])*
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
    (
        $(#[$docs:meta])*
        $libbpf_ty:ident as $name:ident $(with $trait:ident)?
    ) => {
        $(#[$docs])*
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
            #[inline]
            pub fn is_empty(&self) -> bool {
                self.members.is_empty()
            }

            #[doc = ::core::concat!("How many members this [`", ::core::stringify!($name), "`] has")]
            #[inline]
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
        $(#[$docs:meta])*
        $libbpf_ty:ident as $name:ident $(with $trait:ident)?;

        $($rest:tt)+
    ) => {
        $(#[$docs])*
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
    #[inline]
    fn normal(offset: u32) -> Self {
        Self::Normal { offset }
    }

    #[inline]
    fn bif_field(offset: u32) -> Self {
        Self::BitField {
            size: (offset >> 24) as u8,
            offset: offset & 0x00_ff_ff_ff,
        }
    }
}

/// The kind of linkage a variable of function can have.
#[derive(TryFromPrimitive, IntoPrimitive, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Linkage {
    /// Static linkage
    Static = 0,
    /// Global linkage
    Global,
    /// External linkage
    Extern,
    /// Unknown
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
gen_fieldless_concrete_type! {
    /// The representation of the c_void type.
    Void
}

// Int

/// An integer.
///
/// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-int)
#[derive(Debug)]
pub struct Int<'btf> {
    source: BtfType<'btf>,
    /// The encoding of the number.
    pub encoding: IntEncoding,
    /// The offset in bits where the value of this integer starts. Mostly usefull for bitfields in
    /// structs.
    pub offset: u8,
    /// The number of bits in the int. (For example, an u8 has 8 bits).
    pub bits: u8,
}

/// The kinds of ways a btf [Int] can be encoded.
#[derive(Debug)]
pub enum IntEncoding {
    /// No encoding.
    None,
    /// Signed.
    Signed,
    /// It's a c_char.
    Char,
    /// It's a bool.
    Bool,
}

impl<'btf> TryFrom<BtfType<'btf>> for Int<'btf> {
    type Error = BtfType<'btf>;

    fn try_from(t: BtfType<'btf>) -> Result<Self, Self::Error> {
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
                _ => IntEncoding::None,
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
gen_fieldless_concrete_type! {
    /// A pointer.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-ptr)
    Ptr with ReferencesType
}

// Array
gen_concrete_type! {
    /// An array.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-array)
    btf_array as Array
}

impl<'s> Array<'s> {
    /// The type id of the stored type.
    #[inline]
    pub fn ty(&self) -> TypeId {
        self.ptr.type_.into()
    }

    /// The type of index used.
    #[inline]
    pub fn index_ty(&self) -> TypeId {
        self.ptr.index_type.into()
    }

    /// The capacity of the array.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.ptr.nelems as usize
    }

    /// The type contained in this array.
    #[inline]
    pub fn contained_type(&self) -> BtfType<'s> {
        self.source
            .source
            .type_by_id(self.ty())
            .expect("arrays should always reference an existing type")
    }
}

// Struct
gen_collection_concrete_type! {
    /// A struct.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-struct)
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
    /// A Union.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-union)
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

/// A Composite type, which can be one of a [`Struct`] or a [`Union`].
///
/// Sometimes it's not usefull to distinguish them, in that case, one can use this
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
    /// An Enum of at most 32 bits.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-enum)
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
gen_fieldless_concrete_type! {
    /// A forward declared C type.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-fwd)
    Fwd
}

impl Fwd<'_> {
    /// The kind of C type that is forwardly declared.
    pub fn kind(&self) -> FwdKind {
        if self.source.kind_flag() {
            FwdKind::Union
        } else {
            FwdKind::Struct
        }
    }
}

/// The kinds of types that can be forward declared.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum FwdKind {
    /// A struct.
    Struct,
    /// A union.
    Union,
}

// Typedef
gen_fieldless_concrete_type! {
    /// A C typedef.
    ///
    /// References the original type.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-typedef)
    Typedef with ReferencesType
}

// Volatile
gen_fieldless_concrete_type! {
    /// The volatile modifier.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-volatile)
    Volatile with ReferencesType
}

// Const
gen_fieldless_concrete_type! {
    /// The const modifier.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-const)
    Const with ReferencesType
}

// Restrict
gen_fieldless_concrete_type! {
    /// The restrict modifier.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-restrict)
    Restrict with ReferencesType
}

// Func
gen_fieldless_concrete_type! {
    /// A function.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-func)
    Func with ReferencesType
}

impl Func<'_> {
    /// This function's linkage.
    #[inline]
    pub fn linkage(&self) -> Linkage {
        self.source.vlen().try_into().unwrap_or(Linkage::Unknown)
    }
}

// FuncProto
gen_collection_concrete_type! {
    /// A function prototype.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-func-proto)
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
gen_concrete_type! {
    /// A global variable.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-var)
    btf_var as Var with ReferencesType
}

impl Var<'_> {
    /// The kind of linkage this variable has.
    #[inline]
    pub fn linkage(&self) -> Linkage {
        self.ptr.linkage.try_into().unwrap_or(Linkage::Unknown)
    }
}

// DataSec
gen_collection_concrete_type! {
    /// An ELF's data section, such as `.data`, `.bss` or `.rodata`.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-datasec)
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
gen_fieldless_concrete_type! {
    /// A floating point number.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-float)
    Float with HasSize
}

// DeclTag
gen_concrete_type! {
    /// A declaration tag.
    ///
    /// A custom tag the programmer can attach to a symbol.
    ///
    /// See the [clang docs](https://clang.llvm.org/docs/AttributeReference.html#btf-decl-tag) on
    /// it.
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-decl-tag)
    btf_decl_tag as DeclTag with ReferencesType
}

impl DeclTag<'_> {
    /// The component index is present only when the tag points to a struct/union member or a
    /// function argument.
    /// And component_idx indicates which member or argument, this decl tag refers to.
    #[inline]
    pub fn component_index(&self) -> Option<u32> {
        self.ptr.component_idx.try_into().ok()
    }
}

// TypeTag
gen_fieldless_concrete_type! {
    /// A type tag.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-type-tag)
    TypeTag with ReferencesType
}

// Enum64
gen_collection_concrete_type! {
    /// An Enum of 64 bits.
    ///
    /// See also [libbpf docs](https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-enum64)
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

/// A macro that allows matching on the type of a [`BtfType`] as if it was an enum.
///
/// Each pattern can be of two types.
///
/// ```no_run
/// use libbpf_rs::btf::BtfType;
/// use libbpf_rs::btf_type_match;
///
/// # fn do_something_with_an_int(i: libbpf_rs::btf::types::Int) -> &'static str { "" }
/// let ty: BtfType;
/// # ty = todo!();
/// btf_type_match!(match ty {
///     BtfKind::Int(i) => do_something_with_an_int(i),
///     BtfKind::Struct => "it's a struct",
///     BtfKind::Union => {
///         "it's a union"
///     },
///     _ => "default",
/// });
/// ```
///
/// Variable Binding.
///
/// ```compile_fail
///     BtfKind::Int(i) => {
///         // we can use i here and it will be an `Int`
///     }
/// ```
///
/// NonBinding.
///
/// ```compile_fail
///     BtfKind::Int => {
///         // we don't have access to the variable, but we know the scrutinee is an Int
///     }
/// ```
///
/// Multiple Variants
/// ```compile_fail
///     BtfKind::Struct | BtfKind::Union => {
///         // we don't have access to the variable,
///         // but we know the scrutinee is either a Struct or a Union
///     }
/// ```
///
/// Special case for [`Struct`] and [`Union`]: [`Composite`]
/// ```compile_fail
///     BtfKind::Composite(c) => {
///         // we can use `c` as an instance of `Composite`.
///         // this branch will match if the type is either a Struct or a Union.
///     }
/// ```
// $(BtfKind::$name:ident $(($var:ident))? => $action:expr $(,)?)+
#[macro_export]
macro_rules! btf_type_match {
    // base rule
    (
        match $ty:ident {
            $($pattern:tt)+
        }
    ) => {{
        let ty: $crate::btf::BtfType<'_> = $ty;
        $crate::__btf_type_match!(match ty.kind() { } $($pattern)*)
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __btf_type_match {
    /*
     * Composite special case
     *
     * This is similar to simple-match but it's hardcoded for composite which matches both structs
     * and unions.
     */
    (
        match $ty:ident.kind() { $($p:pat => $a:expr),* }
        BtfKind::Composite $( ($var:ident) )? => $action:expr,
        $($rest:tt)*
    ) => {
        $crate::__btf_type_match!(match $ty.kind() { $($p => $a,)* }
            BtfKind::Composite $( ($var) )* => { $action }
            $($rest)*
        )
    };
    (
        match $ty:ident.kind() { $($p:pat => $a:expr),* }
        BtfKind::Composite $(($var:ident))? => $action:block
        $($rest:tt)*
    ) => {
        $crate::__btf_type_match!(match $ty.kind() {
            $($p => $a,)*
            $crate::btf::BtfKind::Struct | $crate::btf::BtfKind::Union => {
                $(let $var = $crate::btf::types::Composite::try_from($ty).unwrap();)*
                $action
            }
        }
             $($rest)*
        )
    };
    // simple-match: match on simple patterns that use an expression followed by a comma
    (
        match $ty:ident.kind() { $($p:pat => $a:expr),* }
        BtfKind::$name:ident $(($var:ident))? => $action:expr,
        $($rest:tt)*
    ) => {
        $crate::__btf_type_match!(
            match $ty.kind() { $($p => $a),* }
            BtfKind::$name $(($var))? => { $action }
            $($rest)*
        )
    };
    // simple-match: match on simple patterns that use a block without a comma
    (
        match $ty:ident.kind() { $($p:pat => $a:expr),* }
        BtfKind::$name:ident $(($var:ident))? => $action:block
        $($rest:tt)*
    ) => {
        $crate::__btf_type_match!(match $ty.kind() {
            $($p => $a,)*
            $crate::btf::BtfKind::$name => {
                $(let $var = $crate::btf::types::$name::try_from($ty).unwrap();)*
                $action
            }
        }
             $($rest)*
        )
    };
    // or-pattern: match on one or more variants without capturing a variable and using an
    //             expression followed by a comma.
    (
        match $ty:ident.kind() { $($p:pat => $a:expr),* }
        $(BtfKind::$name:ident)|+  => $action:expr,
        $($rest:tt)*
    ) => {
        $crate::__btf_type_match!(
            match $ty.kind() { $($p => $a),* }
            $(BtfKind::$name)|* => { $action }
            $($rest)*
        )
    };
    (
        match $ty:ident.kind() { $($p:pat => $a:expr),* }
        $(BtfKind::$name:ident)|+  => $action:block
        $($rest:tt)*
    ) => {
        $crate::__btf_type_match!(match $ty.kind() {
            $($p => $a,)*
            $($crate::btf::BtfKind::$name)|* => {
                $action
            }
        }
             $($rest)*
        )
    };
    // default match case
    //
    // we only need the expression case here because this case is not followed by a $rest:tt like
    // the others, which let's us use the $(,)? pattern.
    (
        match $ty:ident.kind() { $($p:pat => $a:expr),* }
        _ => $action:expr $(,)?
    ) => {
        $crate::__btf_type_match!(match $ty.kind() {
            $($p => $a,)*
            _ => { $action }
        }

        )
    };
    // stop case, where the code is actually generated
    (match $ty:ident.kind() { $($p:pat => $a:expr),*  } ) => {
        match $ty.kind() {
            $($p => $a),*
        }
    }
}

#[cfg(test)]
mod test {
    // creates a dummy btftype, not it's not safe to use this type, but it is safe to match on it,
    // which is all we need for these tests.
    macro_rules! dummy_type {
        ($ty:ident) => {
            let btf = $crate::Btf {
                ptr: std::ptr::NonNull::dangling(),
                drop_policy: $crate::btf::DropPolicy::Nothing,
                _marker: std::marker::PhantomData,
            };
            let $ty = BtfType {
                type_id: $crate::btf::TypeId::from(1),
                name: None,
                source: &btf,
                ty: &libbpf_sys::btf_type::default(),
            };
        };
    }

    fn foo(_: super::Int<'_>) -> &'static str {
        "int"
    }

    use super::BtfType;
    use crate::btf_type_match;
    #[test]
    fn full_switch_case() {
        dummy_type!(ty);
        btf_type_match!(match ty {
            BtfKind::Int(i) => foo(i),
            BtfKind::Struct => "it's a struct",
            BtfKind::Void => "",
            BtfKind::Ptr => "",
            BtfKind::Array => "",
            BtfKind::Union => "",
            BtfKind::Enum => "",
            BtfKind::Fwd => "",
            BtfKind::Typedef => "",
            BtfKind::Volatile => "",
            BtfKind::Const => "",
            BtfKind::Restrict => "",
            BtfKind::Func => "",
            BtfKind::FuncProto => "",
            BtfKind::Var => "",
            BtfKind::DataSec => "",
            BtfKind::Float => "",
            BtfKind::DeclTag => "",
            BtfKind::TypeTag => "",
            BtfKind::Enum64 => "",
        });
    }

    #[test]
    fn partial_match() {
        dummy_type!(ty);
        btf_type_match!(match ty {
            BtfKind::Int => "int",
            _ => "default",
        });
    }

    #[test]
    fn or_pattern_match() {
        dummy_type!(ty);
        // we ask rustfmt to not format this block so that we can keep the trailing `,` in the
        // const | restrict branch.
        #[rustfmt::skip]
        btf_type_match!(match ty {
            BtfKind::Int => "int",
            BtfKind::Struct | BtfKind::Union => "composite",
            BtfKind::Typedef | BtfKind::Volatile => {
                "qualifier"
            }
            BtfKind::Const | BtfKind::Restrict => {
                "const or restrict"
            },
            _ => "default",
        });
    }

    #[test]
    fn match_arm_with_brackets() {
        dummy_type!(ty);
        // we ask rustfmt to not format this block so that we can keep the trailing `,` in the int
        // branch.
        #[rustfmt::skip]
        btf_type_match!(match ty {
            BtfKind::Void => {
                "void"
            }
            BtfKind::Int => {
                "int"
            },
            BtfKind::Struct => "struct",
            _ => "default",
        });
    }

    #[test]
    fn match_on_composite() {
        dummy_type!(ty);
        btf_type_match!(match ty {
            BtfKind::Composite(c) => c.is_struct,
            _ => false,
        });
        btf_type_match!(match ty {
            BtfKind::Composite(c) => {
                c.is_struct
            }
            _ => false,
        });
        // we ask rustfmt to not format this block so that we can keep the trailing `,` in the
        // composite branch.
        #[rustfmt::skip]
        btf_type_match!(match ty {
            BtfKind::Composite(c) => {
                c.is_struct
            },
            _ => false,
        });
    }

    #[test]
    fn match_arm_with_multiple_statements() {
        dummy_type!(ty);

        btf_type_match!(match ty {
            BtfKind::Int(i) => {
                let _ = i;
                "int"
            }
            _ => {
                let _ = 1;
                "default"
            }
        });
    }

    #[test]
    fn non_expression_guards() {
        dummy_type!(ty);

        btf_type_match!(match ty {
            BtfKind::Int => {
                let _ = 1;
                "int"
            }
            BtfKind::Typedef | BtfKind::Const => {
                let _ = 1;
                "qualifier"
            }
            _ => {
                let _ = 1;
                "default"
            }
        });

        btf_type_match!(match ty {
            BtfKind::Int => {
                let _ = 1;
            }
            BtfKind::Typedef | BtfKind::Const => {
                let _ = 1;
            }
            _ => {
                let _ = 1;
            }
        });
    }
}
