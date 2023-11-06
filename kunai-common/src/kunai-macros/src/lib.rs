use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{self, Parse, ParseStream},
    parse_macro_input,
    punctuated::{Pair, Punctuated},
    Attribute, DeriveInput, Error, Ident, ItemFn, LitStr, Token,
};

fn split_on_capital_letters(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut start = 0;

    for (i, c) in s.char_indices().skip(1) {
        if c.is_uppercase() {
            words.push(s[start..i].to_owned());
            start = i;
        }
    }

    words.push(s[start..].to_owned());
    words
}

#[proc_macro_derive(BpfError, attributes(error, generate, wrap))]
pub fn error_derive(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let enum_name = &input.ident;

    let data_enum = match input.data {
        syn::Data::Enum(data_enum) => data_enum,
        _ => panic!("This macro only supports enums."),
    };

    let mut desc_arms = vec![];
    let mut name_arms = vec![];
    // we iterate over the enum variants
    for v in data_enum.variants.iter() {
        // name of the variant
        let name = &v.ident;
        let name_str = name.to_string();

        // we find error attributes associated to the variant
        let err_attr = v.attrs.iter().find(|&attr| attr.path().is_ident("error"));
        let gen_attr = v
            .attrs
            .iter()
            .find(|&attr| attr.path().is_ident("generate"));
        let wrap_attr = v.attrs.iter().find(|&attr| attr.path().is_ident("wrap"));

        if matches!(v.fields, syn::Fields::Unit) {
            name_arms.push(quote!(Self::#name => #name_str,));
        } else {
            let v = vec![quote!(_); v.fields.len()];
            name_arms.push(quote!(Self::#name(#(#v),*) => #name_str,));
        }

        if let Some(err_attr) = err_attr {
            // we expect a literal string
            let args: syn::LitStr = err_attr.parse_args().expect("failed to parse args");

            // we generate a match arm delivering the good error name
            if v.fields.is_empty() {
                desc_arms.push(quote!(Self::#name => #args,));
            } else {
                let v = vec![quote!(_); v.fields.len()];
                desc_arms.push(quote!(Self::#name(#(#v),*) => #args,));
            }
        }

        if gen_attr.is_some() {
            let gen = split_on_capital_letters(&name.to_string())
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect::<Vec<String>>()
                .join(" ");
            if v.fields.is_empty() {
                desc_arms.push(quote!(Self::#name => #gen,));
            } else {
                let v = vec![quote!(_); v.fields.len()];
                desc_arms.push(quote!(Self::#name(#(#v),*) => #gen,));
            }
        }

        if wrap_attr.is_some() {
            if !(v.fields.len() == 1 && matches!(v.fields, syn::Fields::Unnamed(_))) {
                panic!("variant must be unamed with only one field");
            }

            desc_arms.push(quote!(Self::#name(v) => v.description(),));
        }
    }

    quote!(
        impl #enum_name {
            #[inline(always)]
            pub const fn name(&self) -> &'static str {
                match self {
                    #(#name_arms)*
                }
            }

            #[inline(always)]
            pub const fn description(&self) -> &'static str{
                match self {
                    #(#desc_arms)*
                }
            }
        }
    )
    .into()
}

#[proc_macro_derive(StrEnum, attributes(str))]
pub fn str_enum_derive(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let enum_name = &input.ident;

    let data_enum = match input.data {
        syn::Data::Enum(data_enum) => data_enum,
        _ => panic!("This macro only supports enums."),
    };

    let mut as_str_arms = vec![];
    let mut from_str_arms = vec![];
    let mut try_from_uint_arms = vec![];
    let mut variants = vec![];

    // we iterate over the enum variants
    for v in data_enum.variants.iter() {
        // name of the variant
        let name = &v.ident;

        // we find error attributes associated to the variant
        let str_attr = v.attrs.iter().find(|&attr| attr.path().is_ident("str"));

        let args = match str_attr {
            // if there is a #[str()] attribute
            Some(s) => {
                // we expect a literal string
                let args: LitStr = s.parse_args().expect("failed to parse args");
                args.value()
            }
            // by default we take the name of the enum
            None => name.to_string(),
        };

        // we generate a match arm delivering the good error name
        if v.fields.is_empty() {
            as_str_arms.push(quote!(Self::#name => #args,));
            from_str_arms.push(quote!(#args => Ok(Self::#name),));
            variants.push(quote!(Self::#name,));
            try_from_uint_arms.push(quote!(ty if Self::#name as u64 == ty => Ok(Self::#name),));
        } else {
            panic!("enum variant cannot hold values")
        }
    }

    let variants_len = variants.len();

    quote!(
        impl core::str::FromStr for #enum_name {
            type Err = &'static str;

            #[inline]
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    #(#from_str_arms)*
                    _ =>  Err("unknown source string"),
                }
            }
        }

        impl #enum_name {
            #[inline]
            pub fn try_from_uint<T: Into<u64>>(value: T) -> Result<Self, &'static str> {
                match value.into() {
                    #(#try_from_uint_arms)*
                    _ => Err("invalid value"),
                }
            }

            #[inline]
            pub const fn variants() -> [Self;#variants_len]{
                [
                #(#variants)*
                ]
            }

            #[inline(always)]
            pub const fn as_str(&self) -> &'static str{
                match self {
                    #(#as_str_arms)*
                }
            }
        }
    )
    .into()
}

pub(crate) struct NameValue {
    name: Ident,
    value: LitStr,
}

pub(crate) enum Arg {
    String(NameValue),
    Bool(Ident),
}

pub(crate) struct Args {
    pub(crate) args: Vec<Arg>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Args> {
        let args = Punctuated::<Arg, Token![,]>::parse_terminated_with(input, |input| {
            let ident = input.parse::<Ident>()?;
            let lookahead = input.lookahead1();
            if input.is_empty() || lookahead.peek(Token![,]) {
                Ok(Arg::Bool(ident))
            } else if lookahead.peek(Token![=]) {
                let _: Token![=] = input.parse()?;
                Ok(Arg::String(NameValue {
                    name: ident,
                    value: input.parse()?,
                }))
            } else {
                Err(lookahead.error())
            }
        })?
        .into_pairs()
        .map(|pair| match pair {
            Pair::Punctuated(name_val, _) => name_val,
            Pair::End(name_val) => name_val,
        })
        .collect();

        Ok(Args { args })
    }
}

pub(crate) fn pop_string_arg(args: &mut Args, name: &str) -> Option<String> {
    args.args
        .iter()
        .position(|arg| matches!(arg, Arg::String(name_val) if name_val.name == name))
        .map(|index| match args.args.remove(index) {
            Arg::String(v) => v.value.value(),
            _ => panic!("impossible variant"),
        })
}

pub(crate) fn pop_bool_arg(args: &mut Args, name: &str) -> bool {
    args.args
        .iter()
        .position(|arg| matches!(arg, Arg::Bool(ident) if ident == name))
        .map(|index| match args.args.remove(index) {
            Arg::Bool(ident) => ident,
            _ => panic!("impossible variant"),
        })
        .is_some()
}

pub(crate) fn err_on_unknown_args(args: &Args) -> syn::Result<()> {
    if let Some(arg) = args.args.get(0) {
        let tokens = match arg {
            Arg::String(name_val) => name_val.name.clone(),
            Arg::Bool(ident) => ident.clone(),
        };
        return Err(Error::new_spanned(tokens, "invalid argument"));
    }
    Ok(())
}

pub(crate) fn name_arg(args: &mut Args) -> Option<String> {
    pop_string_arg(args, "name")
}

#[proc_macro_attribute]
//pub fn rename_function(input: TokenStream) -> TokenStream {
pub fn rename_function(attrs: TokenStream, input: TokenStream) -> TokenStream {
    // Parse the input tokens as a function

    let mut args = parse_macro_input!(attrs as Args);
    let new_name = pop_string_arg(&mut args, "name").unwrap();
    let input = parse_macro_input!(input as ItemFn);

    // Extract the new name from the attribute
    //let new_name = input_function.sig.ident.clone();

    let fn_vis = &input.vis.clone();
    let attrs = input.attrs.clone();
    let args = input.sig.inputs.clone();
    let ret = input.sig.output;
    let block = input.block;
    let new_name = syn::parse_str::<Ident>(&new_name).unwrap();
    //panic!("{:?}", attrs);

    // Generate the new function with the specified identifier
    let expanded = quote! {
        #[kprobe]
        #fn_vis fn #new_name(#args) #ret
            #block
    };

    // Convert the generated code back into tokens and return them
    TokenStream::from(expanded)
}
