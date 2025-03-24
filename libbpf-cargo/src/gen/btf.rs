use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::fmt::Write;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ops::Deref;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Context as _;
use anyhow::Result;
use libbpf_rs::btf::types;
use libbpf_rs::btf::types::Linkage;
use libbpf_rs::btf::types::MemberAttr;
use libbpf_rs::btf::BtfKind;
use libbpf_rs::btf::BtfType;
use libbpf_rs::btf::TypeId;
use libbpf_rs::btf_type_match;
use libbpf_rs::Btf;
use libbpf_rs::HasSize;
use libbpf_rs::ReferencesType;

use super::canonicalize_internal_map_name;
use super::InternalMapType;

const ANON_PREFIX: &str = "__anon_";


#[derive(Clone, Debug)]
pub(crate) enum Either<A, B> {
    A(A),
    B(B),
}

impl<A, B, T> Iterator for Either<A, B>
where
    A: Iterator<Item = T>,
    B: Iterator<Item = T>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::A(a) => a.next(),
            Self::B(b) => b.next(),
        }
    }
}

impl<A, B, T> ExactSizeIterator for Either<A, B>
where
    A: ExactSizeIterator<Item = T>,
    B: ExactSizeIterator<Item = T>,
{
}


/// Convert an `EnumMember` into a `Enum64Member`.
fn enum64_member_from_enum_member(other: types::EnumMember<'_>) -> types::Enum64Member<'_> {
    types::Enum64Member {
        name: other.name,
        value: other.value.into(),
    }
}


type EitherEnum<'btf> = Either<types::Enum<'btf>, types::Enum64<'btf>>;

impl EitherEnum<'_> {
    fn size(&self) -> usize {
        match self {
            Self::A(t) => t.size(),
            Self::B(t) => t.size(),
        }
    }

    fn is_signed(&self) -> bool {
        match self {
            Self::A(t) => t.is_signed(),
            Self::B(t) => t.is_signed(),
        }
    }

    fn iter(&self) -> impl ExactSizeIterator<Item = types::Enum64Member<'_>> {
        match self {
            Self::A(t) => Either::A(t.iter().map(enum64_member_from_enum_member)),
            Self::B(t) => Either::B(t.iter()),
        }
    }
}

impl<'btf> From<types::Enum<'btf>> for EitherEnum<'btf> {
    fn from(other: types::Enum<'btf>) -> Self {
        Self::A(other)
    }
}

impl<'btf> From<types::Enum64<'btf>> for EitherEnum<'btf> {
    fn from(other: types::Enum64<'btf>) -> Self {
        Self::B(other)
    }
}

impl<'btf> Deref for EitherEnum<'btf> {
    type Target = BtfType<'btf>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::A(t) => t,
            Self::B(t) => t,
        }
    }
}

/// Check whether the provided type is "unsafe" to use.
///
/// A type is considered unsafe by this function if it is not valid for
/// any bit pattern.
fn is_unsafe(ty: BtfType<'_>) -> bool {
    let ty = ty.skip_mods_and_typedefs();

    btf_type_match!(match ty {
        BtfKind::Int(t) => matches!(t.encoding, types::IntEncoding::Bool),
        _ => false,
    })
}

fn is_struct_packed(composite: &types::Composite<'_>, btf: &Btf<'_>) -> Result<bool> {
    if !composite.is_struct {
        return Ok(false);
    }

    let align = composite.alignment()?;

    // Size of a struct has to be a multiple of its alignment
    if composite.size() % align != 0 {
        return Ok(true);
    }

    // All the non-bitfield fields have to be naturally aligned
    for m in composite.iter() {
        let align = btf.type_by_id::<BtfType<'_>>(m.ty).unwrap().alignment()?;

        if let MemberAttr::Normal { offset } = m.attr {
            if offset as usize % (align.get() * 8) != 0 {
                return Ok(true);
            }
        }
    }

    // Even if original struct was marked as packed, we haven't detected any misalignment, so
    // there is no effect of packedness for given struct
    Ok(false)
}

/// Given a `current_offset` (in bytes) into a struct and a `required_offset` (in bytes) that
/// type `type_id` needs to be placed at, returns how much padding must be inserted before
/// `type_id`.
fn required_padding(
    current_offset: usize,
    required_offset: usize,
    ty: &BtfType<'_>,
    packed: bool,
) -> Result<usize> {
    ensure!(
        current_offset <= required_offset,
        "current offset ({current_offset}) ahead of required offset ({required_offset})"
    );

    let align = if packed {
        NonZeroUsize::new(1).unwrap()
    } else {
        // Assume 32-bit alignment in case we're generating code for 32-bit
        // arch. Worst case is on a 64-bit arch the compiler will generate
        // extra padding. The final layout will still be identical to what is
        // described by BTF.
        let a = ty.alignment()?;

        if a.get() > 4 {
            NonZeroUsize::new(4).unwrap()
        } else {
            a
        }
    };

    // If we aren't aligning to the natural offset, padding needs to be inserted
    let aligned_offset = (current_offset + align.get() - 1) / align * align.get();
    if aligned_offset == required_offset {
        Ok(0)
    } else {
        Ok(required_offset - current_offset)
    }
}

struct TypeDeclOpts {
    func_type: &'static str,
}

fn type_declaration_impl(
    ty: BtfType<'_>,
    type_map: &TypeMap,
    opts: &TypeDeclOpts,
) -> Result<String> {
    let ty = ty.skip_mods_and_typedefs();

    let s = btf_type_match!(match ty {
        BtfKind::Void => "std::ffi::c_void".to_string(),
        BtfKind::Int(t) => {
            let width = match (t.bits + 7) / 8 {
                1 => "8",
                2 => "16",
                4 => "32",
                8 => "64",
                16 => "128",
                _ => bail!("Invalid integer width"),
            };

            match t.encoding {
                types::IntEncoding::Signed => format!("i{width}"),
                types::IntEncoding::Bool => {
                    assert!(t.bits as usize == (size_of::<bool>() * 8));
                    "bool".to_string()
                }
                types::IntEncoding::Char | types::IntEncoding::None => format!("u{width}"),
            }
        }
        BtfKind::Float(t) => {
            let width = match t.size() {
                2 => bail!("Unsupported float width"),
                4 => "32",
                8 => "64",
                12 => bail!("Unsupported float width"),
                16 => bail!("Unsupported float width"),
                _ => bail!("Invalid float width"),
            };

            format!("f{width}")
        }
        BtfKind::Ptr(t) => {
            let pointee_ty = type_declaration_impl(t.referenced_type(), type_map, opts)?;

            format!("*mut {pointee_ty}")
        }
        BtfKind::Array(t) => {
            let val_ty = type_declaration_impl(t.contained_type(), type_map, opts)?;

            format!("[{}; {}]", val_ty, t.capacity())
        }
        BtfKind::Struct | BtfKind::Union | BtfKind::Enum | BtfKind::Enum64 =>
            type_map.type_name_or_anon(&ty).into_owned(),
        BtfKind::Func | BtfKind::FuncProto => opts.func_type.to_string(),
        BtfKind::Fwd => "std::ffi::c_void".to_string(),
        BtfKind::Var(t) => type_declaration_impl(t.referenced_type(), type_map, opts)?,
        _ => bail!("Invalid type: {ty:?}"),
    });
    Ok(s)
}

fn type_declaration(ty: BtfType<'_>, type_map: &TypeMap) -> Result<String> {
    let opts = TypeDeclOpts {
        func_type: "std::ffi::c_void",
    };
    type_declaration_impl(ty, type_map, &opts)
}

/// Returns an expression that evaluates to the Default value
/// of a type(typeid) in string form.
///
/// To be used when creating a impl Default for a structure
///
/// Rule of thumb is `ty` must be a type a variable can have.
///
/// Type qualifiers are discarded (eg `const`, `volatile`, etc).
fn type_default(ty: BtfType<'_>, type_map: &TypeMap) -> Result<String> {
    let ty = ty.skip_mods_and_typedefs();

    Ok(btf_type_match!(match ty {
        BtfKind::Int => format!("{}::default()", type_declaration(ty, type_map)?),
        BtfKind::Float => format!("{}::default()", type_declaration(ty, type_map)?),
        BtfKind::Ptr => "std::ptr::null_mut()".to_string(),
        BtfKind::Array(t) => {
            format!(
                "[{}; {}]",
                type_default(t.contained_type(), type_map)
                    .map_err(|err| anyhow!("in {ty:?}: {err}"))?,
                t.capacity()
            )
        }
        BtfKind::Struct | BtfKind::Union | BtfKind::Enum | BtfKind::Enum64 =>
            format!("{}::default()", type_map.type_name_or_anon(&ty)),
        BtfKind::Var(t) => format!(
            "{}::default()",
            type_declaration(t.referenced_type(), type_map)?
        ),
        _ => bail!("Invalid type: {ty:?}"),
    }))
}

fn size_of_type(ty: BtfType<'_>, btf: &Btf<'_>) -> Result<usize> {
    let ty = ty.skip_mods_and_typedefs();

    Ok(btf_type_match!(match ty {
        BtfKind::Int(t) => ((t.bits + 7) / 8).into(),
        BtfKind::Ptr => btf.ptr_size()?.get(),
        BtfKind::Array(t) => t.capacity() * size_of_type(t.contained_type(), btf)?,
        BtfKind::Struct(t) => t.size(),
        BtfKind::Union(t) => t.size(),
        BtfKind::Enum(t) => t.size(),
        BtfKind::Enum64(t) => t.size(),
        BtfKind::Var(t) => size_of_type(t.referenced_type(), btf)?,
        BtfKind::DataSec(t) => t.size(),
        BtfKind::Float(t) => t.size(),
        _ => bail!("Cannot get size of type_id: {ty:?}"),
    }))
}

fn escape_reserved_keyword(identifier: Cow<'_, str>) -> Cow<'_, str> {
    // A list of keywords that need to be escaped in Rust when used for variable
    // names or similar (from https://doc.rust-lang.org/reference/keywords.html#keywords,
    // minus keywords that are already reserved in C).
    let reserved = [
        "Self", "abstract", "as", "async", "await", "become", "box", "crate", "dyn", "enum",
        "final", "fn", "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut",
        "override", "priv", "pub", "ref", "self", "super", "trait", "try", "type", "typeof",
        "unsafe", "unsized", "use", "virtual", "where", "yield", "gen",
    ];
    debug_assert_eq!(
        reserved.as_slice(),
        {
            let mut vec = reserved.to_vec();
            vec.sort();
            vec
        },
        "please keep reserved keywords sorted",
    );

    // Some keywords just cannot be used, even in raw form.
    // See https://internals.rust-lang.org/t/raw-identifiers-dont-work-for-all-identifiers/9094
    let disallowed_raw = ["Self", "crate", "self", "super"];
    debug_assert_eq!(
        disallowed_raw.as_slice(),
        {
            let mut vec = disallowed_raw.to_vec();
            vec.sort();
            vec
        },
        "please keep reserved keywords sorted",
    );

    if reserved.binary_search(&identifier.as_ref()).is_ok() {
        if disallowed_raw.binary_search(&identifier.as_ref()).is_ok() {
            // Just remove the first 'a' or 'e' character. Yes, that could
            // conceivably be the cause of a collision in itself ¯\_(ツ)_/¯
            Cow::Owned(identifier.replacen(['a', 'e'], "", 1))
        } else {
            Cow::Owned(format!("r#{identifier}"))
        }
    } else {
        identifier
    }
}

#[derive(Debug, Default)]
pub(crate) struct TypeMap {
    /// A mapping from type to number, allowing us to assign numbers to
    /// anonymous types consistently.
    types: RefCell<HashMap<TypeId, usize>>,
    /// Mapping from type to name.
    names: RefCell<HashMap<TypeId, String>>,
    /// Mapping from type name to the number of times we have seen this
    /// name already.
    names_count: RefCell<HashMap<String, u8>>,
}

impl TypeMap {
    pub fn type_name_or_anon<'s>(&self, ty: &BtfType<'s>) -> Cow<'s, str> {
        match ty.name() {
            None => {
                let mut anon_table = self.types.borrow_mut();
                let len = anon_table.len() + 1; // use 1 index anon ids for backwards compat
                let anon_id = anon_table.entry(ty.type_id()).or_insert(len);
                format!("{ANON_PREFIX}{anon_id}").into()
            }
            Some(n) => match self.names.borrow_mut().entry(ty.type_id()) {
                Entry::Occupied(entry) => Cow::Owned(entry.get().clone()),
                Entry::Vacant(vacancy) => {
                    let name = n.to_string_lossy();
                    let mut names_count = self.names_count.borrow_mut();
                    let cnt = names_count
                        .entry(name.to_string())
                        .and_modify(|cnt| *cnt += 1)
                        .or_insert(1);
                    if *cnt == 1 {
                        vacancy.insert(name.to_string());
                        name
                    } else {
                        Cow::Owned(vacancy.insert(format!("{name}_{cnt}")).clone())
                    }
                }
            },
        }
    }
}


#[derive(Debug)]
pub(crate) struct GenStructOps<'btf> {
    btf: &'btf GenBtf<'btf>,
    deps: Vec<BtfType<'btf>>,
    vars: Vec<types::Var<'btf>>,
}

impl<'btf> GenStructOps<'btf> {
    pub fn new(btf: &'btf GenBtf<'btf>) -> Result<Self> {
        let mut deps = Vec::new();
        let mut vars = Vec::new();

        // Take all the struct_ops datasec entries and collect their variables
        // (and dependent types).
        for ty in btf.type_by_kind::<types::DataSec<'_>>() {
            let name = match ty.name() {
                Some(s) => s.to_str().context("datasec has invalid name")?,
                None => "",
            };

            if !matches!(
                canonicalize_internal_map_name(name),
                Some(InternalMapType::StructOps)
            ) {
                continue;
            }

            for var in ty.iter() {
                let var = btf
                    .type_by_id::<types::Var<'_>>(var.ty)
                    .ok_or_else(|| anyhow!("datasec type does not point to a variable"))?;

                if var.linkage() == types::Linkage::Static {
                    // do not output Static Var
                    continue;
                }

                let () = vars.push(var);

                if let Some(next_ty) = next_type(*var)? {
                    let () = deps.push(next_ty);
                }
            }
        }

        let slf = Self { btf, deps, vars };
        Ok(slf)
    }

    pub fn gen_struct_ops_def(&self, def: &mut String) -> Result<()> {
        // Emit a single struct_ops type definition containing all
        // variables discovered earlier.
        write!(
            def,
            r#"
#[derive(Debug, Clone)]
#[repr(C)]
pub struct StructOps {{
"#
        )?;

        for var in self.vars.iter() {
            writeln!(
                def,
                r#"    pub {var_name}: *mut types::{var_type},"#,
                var_name = var.name().unwrap().to_string_lossy(),
                var_type = self.btf.type_declaration(**var)?
            )?;
        }

        writeln!(def, "}}")?;

        write!(
            def,
            r#"
impl StructOps {{
"#
        )?;

        for var in self.vars.iter() {
            write!(
                def,
                r#"
    pub fn {var_name}(&self) -> &types::{var_type} {{
        // SAFETY: The library ensures that the member is pointing to
        //         valid data.
        unsafe {{ self.{var_name}.as_ref() }}.unwrap()
    }}

    pub fn {var_name}_mut(&mut self) -> &mut types::{var_type} {{
        // SAFETY: The library ensures that the member is pointing to
        //         valid data.
        unsafe {{ self.{var_name}.as_mut() }}.unwrap()
    }}
"#,
                var_name = var.name().unwrap().to_string_lossy(),
                var_type = self.btf.type_declaration(**var)?
            )?;
        }

        writeln!(def, "}}")?;
        Ok(())
    }

    pub fn gen_dependent_types(
        mut self,
        processed: &mut HashSet<TypeId>,
        def: &mut String,
    ) -> Result<()> {
        let vars = self
            .vars
            .iter()
            .map(|ty| ty.next_type().unwrap().type_id())
            .collect::<HashSet<_>>();

        while !self.deps.is_empty() {
            let ty = self.deps.remove(0);
            if !processed.insert(ty.type_id()) {
                continue;
            }

            btf_type_match!(match ty {
                BtfKind::Composite(t) => {
                    if vars.contains(&ty.type_id()) {
                        let opts = TypeDeclOpts {
                            func_type: "libbpf_rs::libbpf_sys::bpf_program",
                        };
                        self.btf.type_definition_for_composites_with_opts(
                            def,
                            &mut self.deps,
                            t,
                            &opts,
                        )?
                    } else {
                        self.btf
                            .type_definition_for_composites(def, &mut self.deps, t)?
                    }
                }
                BtfKind::Enum(t) => self.btf.type_definition_for_enums(def, t.into())?,
                BtfKind::Enum64(t) => self.btf.type_definition_for_enums(def, t.into())?,
                _ => bail!("Invalid type: {:?}", ty.kind()),
            });
        }

        Ok(())
    }
}


pub(crate) struct GenBtf<'s> {
    btf: Btf<'s>,
    type_map: TypeMap,
}

impl Debug for GenBtf<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("GenBtf<'_>")
            .field("btf", &self.btf)
            .finish()
    }
}

impl<'s> From<Btf<'s>> for GenBtf<'s> {
    fn from(btf: Btf<'s>) -> GenBtf<'s> {
        Self {
            btf,
            type_map: Default::default(),
        }
    }
}

impl<'s> Deref for GenBtf<'s> {
    type Target = Btf<'s>;
    fn deref(&self) -> &Self::Target {
        &self.btf
    }
}

impl<'s> GenBtf<'s> {
    /// Returns the rust-ified type declaration of `ty` in string format.
    ///
    /// Rule of thumb is `ty` must be a type a variable can have.
    ///
    /// Type qualifiers are discarded (eg `const`, `volatile`, etc).
    pub fn type_declaration(&self, ty: BtfType<'s>) -> Result<String> {
        type_declaration(ty, &self.type_map)
    }

    /// Returns an expression that evaluates to the Default value
    /// of a type(typeid) in string form.
    ///
    /// To be used when creating a impl Default for a structure
    ///
    /// Rule of thumb is `ty` must be a type a variable can have.
    ///
    /// Type qualifiers are discarded (eg `const`, `volatile`, etc).
    fn type_default(&self, ty: BtfType<'s>) -> Result<String> {
        type_default(ty, &self.type_map)
    }

    /// Returns rust type definition of `ty` in string format, including dependent types.
    ///
    /// `ty` must be a struct, union, enum, or datasec type.
    pub fn type_definition(
        &self,
        ty: BtfType<'s>,
        processed: &mut HashSet<TypeId>,
    ) -> Result<String> {
        let is_terminal = |ty: BtfType<'_>| -> bool {
            matches!(
                ty.kind(),
                BtfKind::Void
                    | BtfKind::Int
                    | BtfKind::Float
                    | BtfKind::Ptr
                    | BtfKind::Array
                    | BtfKind::Fwd
                    | BtfKind::Typedef
                    | BtfKind::Volatile
                    | BtfKind::Const
                    | BtfKind::Restrict
                    | BtfKind::Func
                    | BtfKind::FuncProto
                    | BtfKind::Var
                    | BtfKind::DeclTag
                    | BtfKind::TypeTag,
            )
        };

        if is_terminal(ty) {
            return Ok(String::new());
        }

        // Process dependent types until there are none left.
        //
        // When we hit a terminal, we write out some stuff. A non-terminal adds more types to
        // the queue.
        let mut def = String::new();
        let mut dependent_types = vec![ty];
        while !dependent_types.is_empty() {
            let ty = dependent_types.remove(0);
            if !processed.insert(ty.type_id()) {
                continue;
            }

            btf_type_match!(match ty {
                BtfKind::Composite(t) =>
                    self.type_definition_for_composites(&mut def, &mut dependent_types, t)?,
                BtfKind::Enum(t) => self.type_definition_for_enums(&mut def, t.into())?,
                BtfKind::Enum64(t) => self.type_definition_for_enums(&mut def, t.into())?,
                BtfKind::DataSec(t) =>
                    self.type_definition_for_datasec(&mut def, &mut dependent_types, t)?,
                _ => bail!("Invalid type: {:?}", ty.kind()),
            });
        }

        Ok(def)
    }

    fn type_definition_for_composites<'a>(
        &'a self,
        def: &mut String,
        dependent_types: &mut Vec<BtfType<'a>>,
        t: types::Composite<'_>,
    ) -> Result<()> {
        let opts = TypeDeclOpts {
            func_type: "std::ffi::c_void",
        };
        self.type_definition_for_composites_with_opts(def, dependent_types, t, &opts)
    }

    fn type_definition_for_composites_with_opts<'a>(
        &'a self,
        def: &mut String,
        dependent_types: &mut Vec<BtfType<'a>>,
        t: types::Composite<'_>,
        opts: &TypeDeclOpts,
    ) -> Result<()> {
        if t.is_empty_union() {
            // Ignore empty union; Rust does not allow unions with no fields.
            return Ok(());
        }

        let packed = is_struct_packed(&t, &self.btf)?;

        // fields in the aggregate
        let mut agg_content: Vec<String> = Vec::new();

        // structs with arrays > 32 length need to impl Default
        // rather than #[derive(Default)]
        let mut impl_default: Vec<String> = Vec::new(); // output for impl Default
        let mut gen_impl_default = false; // whether to output impl Default or use #[derive]

        let mut offset = 0; // In bytes
        for member in t.iter() {
            let member_offset = match member.attr {
                MemberAttr::Normal { offset } => offset,
                // Bitfields are tricky to get correct, if at all possible. For
                // now we just skip them, which results in them being covered by
                // padding bytes.
                MemberAttr::BitField { .. } => continue,
            };

            let field_ty = self
                .type_by_id::<BtfType<'_>>(member.ty)
                .unwrap()
                .skip_mods_and_typedefs();

            if let Ok(composite) = TryInto::<types::Composite<'_>>::try_into(field_ty) {
                if composite.is_empty_union() {
                    // Skip empty union field; we do not generate a type for them.
                    continue;
                }
            }

            if let Some(next_ty_id) = next_type(field_ty)? {
                dependent_types.push(next_ty_id);
            }
            let field_name = if let Some(name) = member.name {
                escape_reserved_keyword(name.to_string_lossy())
            } else {
                // Only anonymous unnamed unions should ever have no name set.
                // We just name them the same as their anonymous type. As there
                // can only be one member of this very type, there can't be a
                // conflict.
                self.type_map.type_name_or_anon(&field_ty)
            };

            // Add padding as necessary
            if t.is_struct {
                let padding = required_padding(
                    offset,
                    member_offset as usize / 8,
                    &self.type_by_id::<BtfType<'_>>(member.ty).unwrap(),
                    packed,
                )?;

                if padding != 0 {
                    agg_content.push(format!(r#"    pub __pad_{offset}: [u8; {padding}],"#,));

                    impl_default.push(format!(
                        r#"            __pad_{offset}: [u8::default(); {padding}]"#,
                    ));

                    if padding > 32 {
                        gen_impl_default = true;
                    }
                }

                if let Some(ft) = self.type_by_id::<types::Array<'_>>(field_ty.type_id()) {
                    if ft.capacity() > 32 {
                        gen_impl_default = true
                    }

                    if self.type_by_id::<types::Ptr<'_>>(ft.ty()).is_some() {
                        gen_impl_default = true
                    }
                }

                // Rust does not implement `Default` for pointers, no matter if
                // the pointee implements it, and it also doesn't do it for
                // `MaybeUninit` constructs, which we use for "unsafe" types.
                if self
                    .type_by_id::<types::Ptr<'_>>(field_ty.type_id())
                    .is_some()
                    || is_unsafe(field_ty)
                {
                    gen_impl_default = true
                }
            }

            match self.type_default(field_ty) {
                Ok(mut def) => {
                    if is_unsafe(field_ty) {
                        def = format!("std::mem::MaybeUninit::new({def})")
                    }

                    impl_default.push(format!(
                        r#"            {field_name}: {field_ty_str}"#,
                        field_ty_str = def
                    ));
                }
                Err(e) => {
                    if gen_impl_default || !t.is_struct {
                        return Err(e.context("Could not construct a necessary Default Impl"));
                    }
                }
            };

            // Set `offset` to end of current var
            offset = (member_offset / 8) as usize + size_of_type(field_ty, &self.btf)?;

            let field_ty_str = type_declaration_impl(field_ty, &self.type_map, opts)?;
            let field_ty_str = if is_unsafe(field_ty) {
                Cow::Owned(format!("std::mem::MaybeUninit<{field_ty_str}>"))
            } else {
                Cow::Borrowed(field_ty_str.as_str())
            };

            agg_content.push(format!(r#"    pub {field_name}: {field_ty_str},"#));
        }

        if t.is_struct {
            let struct_size = t.size();
            let padding = required_padding(offset, struct_size, &t, packed)?;
            if padding != 0 {
                agg_content.push(format!(r#"    pub __pad_{offset}: [u8; {padding}],"#,));
                impl_default.push(format!(
                    r#"            __pad_{offset}: [u8::default(); {padding}]"#,
                ));

                if padding > 32 {
                    gen_impl_default = true;
                }
            }
        }

        if !gen_impl_default && t.is_struct {
            writeln!(def, r#"#[derive(Debug, Default, Copy, Clone)]"#)?;
        } else if t.is_struct {
            writeln!(def, r#"#[derive(Debug, Copy, Clone)]"#)?;
        } else {
            writeln!(def, r#"#[derive(Copy, Clone)]"#)?;
        }

        let aggregate_type = if t.is_struct { "struct" } else { "union" };
        let packed_repr = if packed { ", packed" } else { "" };

        writeln!(def, r#"#[repr(C{packed_repr})]"#)?;
        writeln!(
            def,
            r#"pub {aggregate_type} {name} {{"#,
            name = self.type_map.type_name_or_anon(&t),
        )?;

        for field in agg_content {
            writeln!(def, "{field}")?;
        }
        writeln!(def, "}}")?;

        // if required write a Default implementation for this struct
        if gen_impl_default {
            writeln!(
                def,
                r#"impl Default for {} {{"#,
                self.type_map.type_name_or_anon(&t),
            )?;
            writeln!(def, r#"    fn default() -> Self {{"#)?;
            writeln!(def, r#"        Self {{"#,)?;
            for impl_def in impl_default {
                writeln!(def, r#"{impl_def},"#)?;
            }
            writeln!(def, r#"        }}"#)?;
            writeln!(def, r#"    }}"#)?;
            writeln!(def, r#"}}"#)?;
        } else if !t.is_struct {
            // write a Debug implementation for a union
            writeln!(
                def,
                r#"impl std::fmt::Debug for {} {{"#,
                self.type_map.type_name_or_anon(&t),
            )?;
            writeln!(
                def,
                r#"    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"#
            )?;
            writeln!(def, r#"        write!(f, "(???)")"#)?;
            writeln!(def, r#"    }}"#)?;
            writeln!(def, r#"}}"#)?;

            // write a Default implementation for a union
            writeln!(
                def,
                r#"impl Default for {} {{"#,
                self.type_map.type_name_or_anon(&t),
            )?;
            writeln!(def, r#"    fn default() -> Self {{"#)?;
            writeln!(def, r#"        Self {{"#,)?;
            writeln!(def, r#"{},"#, impl_default[0])?;
            writeln!(def, r#"        }}"#)?;
            writeln!(def, r#"    }}"#)?;
            writeln!(def, r#"}}"#)?;
        }
        Ok(())
    }

    fn type_definition_for_enums(&self, def: &mut String, t: EitherEnum<'_>) -> Result<()> {
        let repr_size = match t.size() {
            1 => "8",
            2 => "16",
            4 => "32",
            8 => "64",
            16 => "128",
            _ => bail!("Invalid enum size: {}", t.size()),
        };

        let enum_name = self.type_map.type_name_or_anon(&t);
        let signed = if t.is_signed() { "i" } else { "u" };
        let mut first_field = None;

        writeln!(def, r#"#[derive(Debug, Copy, Clone, Eq, PartialEq)]"#)?;
        writeln!(def, r#"#[repr(transparent)]"#)?;
        writeln!(def, r#"pub struct {enum_name}(pub {signed}{repr_size});"#)?;
        writeln!(def, "#[allow(non_upper_case_globals)]")?;
        writeln!(def, r#"impl {enum_name} {{"#,)?;

        for value in t.iter() {
            first_field = first_field.or(Some(value));

            writeln!(
                def,
                r#"    pub const {name}: {enum_name} = {enum_name}({value});"#,
                name = value.name.unwrap().to_string_lossy(),
                value = value.value,
            )?;
        }

        writeln!(def, r#"}}"#)?;

        if let Some(first_field) = first_field {
            writeln!(def, r#"impl Default for {enum_name} {{"#)?;
            writeln!(
                def,
                r#"    fn default() -> Self {{ {enum_name}::{name} }}"#,
                name = first_field.name.unwrap().to_string_lossy()
            )?;
            writeln!(def, r#"}}"#)?;
        }

        Ok(())
    }

    fn type_definition_for_datasec<'a>(
        &'a self,
        def: &mut String,
        dependent_types: &mut Vec<BtfType<'a>>,
        t: types::DataSec<'_>,
    ) -> Result<()> {
        let sec_name = match t.name().map(|s| s.to_string_lossy().into_owned()) {
            None => bail!("Datasec name is empty"),
            Some(mut s) if s.starts_with('.') => {
                s.remove(0);
                s
            }
            Some(s) => s,
        };
        let sec_name = sec_name.replace('.', "_");

        // Don't generate anything for ksyms. The BTF is patched up by libbpf at
        // load time and the result can contain multiple variables with the same
        // name, which is could result in invalid generated code.
        if sec_name == "ksyms" {
            return Ok(())
        }

        writeln!(def, r#"#[derive(Debug, Copy, Clone)]"#)?;
        writeln!(def, r#"#[repr(C)]"#)?;
        writeln!(def, r#"pub struct {sec_name} {{"#)?;

        let mut offset: u32 = 0;
        for datasec_var in t.iter() {
            let var = self
                .type_by_id::<types::Var<'_>>(datasec_var.ty)
                .ok_or_else(|| anyhow!("BTF is invalid! Datasec var does not point to a var"))?;

            if var.linkage() == Linkage::Static {
                // do not output Static Var
                continue;
            }

            if let Some(next_ty) = next_type(*var)? {
                dependent_types.push(next_ty);
            }

            let padding =
                required_padding(offset as usize, datasec_var.offset as usize, &var, false)?;
            if padding != 0 {
                writeln!(def, r#"    __pad_{offset}: [u8; {padding}],"#)?;
            }

            // Set `offset` to end of current var
            offset = datasec_var.offset + datasec_var.size as u32;

            writeln!(
                def,
                r#"    pub {var_name}: {var_type},"#,
                var_name = var.name().unwrap().to_string_lossy(),
                var_type = self.type_declaration(*var)?
            )?;
        }

        writeln!(def, "}}")?;
        Ok(())
    }
}

fn next_type(mut t: BtfType<'_>) -> Result<Option<BtfType<'_>>> {
    loop {
        match t.kind() {
            BtfKind::Struct
            | BtfKind::Union
            | BtfKind::Enum
            | BtfKind::Enum64
            | BtfKind::DataSec => return Ok(Some(t)),
            BtfKind::Array => {
                let a = types::Array::try_from(t).unwrap();
                t = a.contained_type()
            }
            _ => match t.next_type() {
                Some(next) => t = next,
                None => return Ok(None),
            },
        }
    }
}
