use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Write;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::ops::Deref;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
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

const ANON_PREFIX: &str = "__anon_";

pub struct GenBtf<'s> {
    btf: Btf<'s>,
    // We use refcell here because the design of this type unfortunately causes a lot of borrowing
    // issues. (Taking BtfType as an argument of a &mut self method requires having multiple
    // borrows of self, since BtfType borrows from self).
    //
    // This way we avoid having any of those issues as we use internal mutability.
    anon_types: RefCell<HashMap<TypeId, usize>>,
}

impl<'s> From<Btf<'s>> for GenBtf<'s> {
    fn from(btf: Btf<'s>) -> GenBtf<'s> {
        Self {
            btf,
            anon_types: Default::default(),
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
    fn size_of(&self, ty: BtfType<'s>) -> Result<usize> {
        let ty = ty.skip_mods_and_typedefs();

        Ok(btf_type_match!(match ty {
            BtfKind::Int(t) => ((t.bits + 7) / 8).into(),
            BtfKind::Ptr => self.ptr_size()?.get(),
            BtfKind::Array(t) => t.capacity() * self.size_of(t.contained_type())?,
            BtfKind::Struct(t) => t.size(),
            BtfKind::Union(t) => t.size(),
            BtfKind::Enum(t) => t.size(),
            BtfKind::Enum64(t) => t.size(),
            BtfKind::Var(t) => self.size_of(t.referenced_type())?,
            BtfKind::DataSec(t) => t.size(),
            BtfKind::Float(t) => t.size(),
            _ => bail!("Cannot get size of type_id: {ty:?}"),
        }))
    }

    fn get_type_name_handling_anon_types(&self, t: &BtfType<'s>) -> Cow<'s, str> {
        match t.name() {
            None => {
                let mut anon_table = self.anon_types.borrow_mut();
                let len = anon_table.len() + 1; // use 1 index anon ids for backwards compat
                let anon_id = anon_table.entry(t.type_id()).or_insert(len);
                format!("{ANON_PREFIX}{anon_id}").into()
            }
            Some(n) => n.to_string_lossy(),
        }
    }

    /// Returns the rust-ified type declaration of `ty` in string format.
    ///
    /// Rule of thumb is `ty` must be a type a variable can have.
    ///
    /// Type qualifiers are discarded (eg `const`, `volatile`, etc).
    pub fn type_declaration(&self, ty: BtfType<'s>) -> Result<String> {
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
                let pointee_ty = self.type_declaration(t.referenced_type())?;

                format!("*mut {pointee_ty}")
            }
            BtfKind::Array(t) => {
                let val_ty = self.type_declaration(t.contained_type())?;

                format!("[{}; {}]", val_ty, t.capacity())
            }
            BtfKind::Struct | BtfKind::Union | BtfKind::Enum | BtfKind::Enum64 =>
                self.get_type_name_handling_anon_types(&ty).into_owned(),
            // The only way a variable references a function is through a function pointer.
            // Return c_void here so the final def will look like `*mut c_void`.
            //
            // It's not like rust code can call a function inside a bpf prog either so we don't
            // really need a full definition. `void *` is totally sufficient for sharing a pointer.
            BtfKind::Func | BtfKind::FuncProto => "std::ffi::c_void".to_string(),
            BtfKind::Var(t) => self.type_declaration(t.referenced_type())?,
            _ => bail!("Invalid type: {ty:?}"),
        });
        Ok(s)
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
        let ty = ty.skip_mods_and_typedefs();

        Ok(btf_type_match!(match ty {
            BtfKind::Void => bail!("Invalid type: {ty:?}"),
            BtfKind::Int => format!("{}::default()", self.type_declaration(ty)?),
            BtfKind::Float => format!("{}::default()", self.type_declaration(ty)?),
            BtfKind::Ptr => "std::ptr::null_mut()".to_string(),
            BtfKind::Array(t) => {
                format!(
                    "[{}; {}]",
                    self.type_default(t.contained_type())
                        .map_err(|err| anyhow!("in {ty:?}: {err}"))?,
                    t.capacity()
                )
            }
            BtfKind::Struct | BtfKind::Union | BtfKind::Enum | BtfKind::Enum64 =>
                format!("{}::default()", self.get_type_name_handling_anon_types(&ty)),
            BtfKind::Var(t) =>
                format!("{}::default()", self.type_declaration(t.referenced_type())?),
            _ => bail!("Invalid type: {ty:?}"),
        }))
    }

    fn is_struct_packed(&self, composite: &types::Composite<'_>) -> Result<bool> {
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
            let align = self.type_by_id::<BtfType<'_>>(m.ty).unwrap().alignment()?;

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
        &self,
        current_offset: usize,
        required_offset: usize,
        ty: &BtfType<'s>,
        packed: bool,
    ) -> Result<usize> {
        ensure!(
            current_offset <= required_offset,
            "Current offset ahead of required offset"
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

    /// Returns rust type definition of `ty` in string format, including dependent types.
    ///
    /// `ty` must be a struct, union, enum, or datasec type.
    pub fn type_definition(&self, ty: BtfType<'s>) -> Result<String> {
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

        ensure!(
            !is_terminal(ty),
            "Tried to print type definition for terminal type"
        );

        // Process dependent types until there are none left.
        //
        // When we hit a terminal, we write out some stuff. A non-terminal adds more types to
        // the queue.
        let mut def = String::new();
        let mut dependent_types = vec![ty];
        let mut processed = BTreeSet::new();
        while !dependent_types.is_empty() {
            let ty = dependent_types.remove(0);
            if processed.contains(&ty.type_id()) {
                continue;
            } else {
                processed.insert(ty.type_id());
            }

            btf_type_match!(match ty {
                BtfKind::Composite(t) =>
                    self.type_definition_for_composites(&mut def, &mut dependent_types, t)?,
                BtfKind::Enum(t) => self.type_definition_for_enums(&mut def, t)?,
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
        let packed = self.is_struct_packed(&t)?;

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
                _ => bail!("Struct bitfields not supported"),
            };

            let field_ty = self
                .type_by_id::<BtfType<'_>>(member.ty)
                .unwrap()
                .skip_mods_and_typedefs();
            if let Some(next_ty_id) = next_type(field_ty)? {
                dependent_types.push(next_ty_id);
            }

            // Add padding as necessary
            if t.is_struct {
                let padding = self.required_padding(
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
                }

                if let Some(ft) = self.type_by_id::<types::Array<'_>>(field_ty.type_id()) {
                    if ft.capacity() > 32 {
                        gen_impl_default = true
                    }
                }

                // Rust does not implement `Default` for pointers, no matter if
                // the pointee implements it.
                if self
                    .type_by_id::<types::Ptr<'_>>(field_ty.type_id())
                    .is_some()
                {
                    gen_impl_default = true
                }
            }

            match self.type_default(field_ty) {
                Ok(def) => {
                    impl_default.push(format!(
                        r#"            {field_name}: {field_ty_str}"#,
                        field_name = if let Some(name) = member.name {
                            name.to_string_lossy()
                        } else {
                            self.get_type_name_handling_anon_types(&field_ty)
                        },
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
            offset = (member_offset / 8) as usize + self.size_of(field_ty)?;

            let field_ty_str = self.type_declaration(field_ty)?;
            let field_name = if let Some(name) = member.name {
                name.to_string_lossy()
            } else {
                field_ty_str.as_str().into()
            };

            agg_content.push(format!(r#"    pub {field_name}: {field_ty_str},"#));
        }

        if t.is_struct {
            let struct_size = t.size();
            let padding = self.required_padding(offset, struct_size, &t, packed)?;
            if padding != 0 {
                agg_content.push(format!(r#"    pub __pad_{offset}: [u8; {padding}],"#,));
                impl_default.push(format!(
                    r#"            __pad_{offset}: [u8::default(); {padding}]"#,
                ));
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
            r#"pub {agg_type} {name} {{"#,
            agg_type = aggregate_type,
            name = self.get_type_name_handling_anon_types(&t),
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
                self.get_type_name_handling_anon_types(&t),
            )?;
            writeln!(def, r#"    fn default() -> Self {{"#)?;
            writeln!(
                def,
                r#"        {} {{"#,
                self.get_type_name_handling_anon_types(&t)
            )?;
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
                self.get_type_name_handling_anon_types(&t),
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
                self.get_type_name_handling_anon_types(&t),
            )?;
            writeln!(def, r#"    fn default() -> Self {{"#)?;
            writeln!(
                def,
                r#"        {} {{"#,
                self.get_type_name_handling_anon_types(&t)
            )?;
            writeln!(def, r#"{},"#, impl_default[0])?;
            writeln!(def, r#"        }}"#)?;
            writeln!(def, r#"    }}"#)?;
            writeln!(def, r#"}}"#)?;
        }
        Ok(())
    }

    fn type_definition_for_enums(&self, def: &mut String, t: types::Enum<'_>) -> Result<()> {
        let repr_size = match t.size() {
            1 => "8",
            2 => "16",
            4 => "32",
            8 => "64",
            16 => "128",
            _ => bail!("Invalid enum size: {}", t.size()),
        };

        let mut signed = "u";
        for value in t.iter() {
            if value.value < 0 {
                signed = "i";
                break;
            }
        }

        writeln!(
            def,
            r#"#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]"#
        )?;
        writeln!(def, r#"#[repr({signed}{repr_size})]"#)?;
        writeln!(
            def,
            r#"pub enum {name} {{"#,
            name = self.get_type_name_handling_anon_types(&t),
        )?;

        for (i, value) in t.iter().enumerate() {
            if i == 0 {
                writeln!(def, r#"    #[default]"#)?;
            }
            writeln!(
                def,
                r#"    {name} = {value},"#,
                name = value.name.unwrap().to_string_lossy(),
                value = value.value,
            )?;
        }

        writeln!(def, "}}")?;
        Ok(())
    }

    fn type_definition_for_datasec<'a>(
        &'a self,
        def: &mut String,
        dependent_types: &mut Vec<BtfType<'a>>,
        t: types::DataSec<'_>,
    ) -> Result<()> {
        let mut sec_name = match t.name().map(|s| s.to_string_lossy()) {
            None => bail!("Datasec name is empty"),
            Some(s) if !s.starts_with('.') => bail!("Datasec name is invalid: {s}"),
            Some(s) => s.into_owned(),
        };
        sec_name.remove(0);

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
                self.required_padding(offset as usize, datasec_var.offset as usize, &var, false)?;
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
