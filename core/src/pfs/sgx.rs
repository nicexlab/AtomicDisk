pub const KEYID_SIZE: usize = 32;

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e)
    };
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

#[macro_export]
macro_rules! impl_struct_default {
    ($($t:ty;)*) => {$(
        impl ::core::default::Default for $t {
            fn default() -> $t {
                unsafe { ::core::mem::transmute([0_u8; ::core::mem::size_of::<$t>()]) }
            }
        }
    )*}
}

pub unsafe trait ContiguousMemory {}

#[macro_export]
macro_rules! impl_struct_ContiguousMemory {
    ($($t:ty;)*) => {$(
        unsafe impl crate::pfs::sgx::ContiguousMemory for $t {}
    )*}
}

#[macro_export]
macro_rules! impl_enum {
    (
        #[repr($repr:ident)]
        #[derive($($derive:meta),*)]
        pub enum $name:ident {
            $key:ident = $val:expr,
            $($keys:ident = $vals:expr,)*
        }
    ) => (
        #[repr($repr)]
        #[derive($($derive),*)]
        pub enum $name {
            $key = $val,
            $($keys = $vals,)*
        }

        impl ::core::default::Default for $name {
            fn default() -> $name {
                 $name::$key
            }
        }

        impl ::core::convert::TryFrom<$repr> for $name {
            type Error = ::core::num::TryFromIntError;
            fn try_from(v: $repr) -> Result<Self, Self::Error> {
                match v {
                    $val => Ok($name::$key),
                    $($vals => Ok($name::$keys),)*
                    _ => Err(u8::try_from(256_u16).unwrap_err()),
                }
            }
        }

        impl ::core::convert::From<$name> for $repr {
            fn from(n: $name) -> $repr {
                match n {
                    $name::$key => $val,
                    $($name::$keys => $vals,)*
                }
            }
        }

        unsafe impl crate::pfs::sgx::ContiguousMemory for $name {}
    )
}

#[macro_export]
macro_rules! impl_asref_slice {
    ($($t:ty;)*) => {$(
        impl ::core::convert::AsRef<[u8]> for $t {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                unsafe { &*(self as *const _ as *const [u8; ::core::mem::size_of::<$t>()]) }
            }
        }
    )*}
}

#[macro_export]
macro_rules! impl_asmut_slice {
    ($($t:ty;)*) => {$(
        impl ::core::convert::AsMut<[u8]> for $t {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                unsafe { &mut *(self as *mut _ as *mut [u8; ::core::mem::size_of::<$t>()]) }
            }
        }
    )*}
}

#[macro_export]
macro_rules! cfg_if {
    // match if/else chains with a final `else`
    (
        $(
            if #[cfg( $i_meta:meta )] { $( $i_tokens:tt )* }
        ) else+
        else { $( $e_tokens:tt )* }
    ) => {
        $crate::cfg_if! {
            @__items () ;
            $(
                (( $i_meta ) ( $( $i_tokens )* )) ,
            )+
            (() ( $( $e_tokens )* )) ,
        }
    };

    // match if/else chains lacking a final `else`
    (
        if #[cfg( $i_meta:meta )] { $( $i_tokens:tt )* }
        $(
            else if #[cfg( $e_meta:meta )] { $( $e_tokens:tt )* }
        )*
    ) => {
        $crate::cfg_if! {
            @__items () ;
            (( $i_meta ) ( $( $i_tokens )* )) ,
            $(
                (( $e_meta ) ( $( $e_tokens )* )) ,
            )*
        }
    };

    // Internal and recursive macro to emit all the items
    //
    // Collects all the previous cfgs in a list at the beginning, so they can be
    // negated. After the semicolon is all the remaining items.
    (@__items ( $( $_:meta , )* ) ; ) => {};
    (
        @__items ( $( $no:meta , )* ) ;
        (( $( $yes:meta )? ) ( $( $tokens:tt )* )) ,
        $( $rest:tt , )*
    ) => {
        // Emit all items within one block, applying an appropriate #[cfg]. The
        // #[cfg] will require all `$yes` matchers specified and must also negate
        // all previous matchers.
        #[cfg(all(
            $( $yes , )?
            not(any( $( $no ),* ))
        ))]
        $crate::cfg_if! { @__identity $( $tokens )* }

        // Recurse to emit all other items in `$rest`, and when we do so add all
        // our `$yes` matchers to the list of `$no` matchers as future emissions
        // will have to negate everything we just matched as well.
        $crate::cfg_if! {
            @__items ( $( $no , )* $( $yes , )? ) ;
            $( $rest , )*
        }
    };

    // Internal macro to make __apply work out right for different match types,
    // because of how macros match/expand stuff.
    (@__identity $( $tokens:tt )* ) => {
        $( $tokens )*
    };
}

#[macro_export]
macro_rules! impl_bitflags {
    (
        $(#[$outer:meta])*
        pub struct $BitFlags:ident: $T:ty {
            $(
                const $Flag:ident = $value:expr;
            )+
        }
    )
    => (
        $(#[$outer])*
        pub struct $BitFlags($T);

        impl $BitFlags {
            $(
                pub const $Flag: $BitFlags = $BitFlags($value);
            )+

            #[inline]
            pub const fn empty() -> $BitFlags {
                $BitFlags(0)
            }

            #[inline]
            pub const fn all() -> $BitFlags {
                $BitFlags($($value)|+)
            }

            #[inline]
            pub const fn bits(&self) -> $T {
                self.0
            }

            #[inline]
            pub fn from_bits(bits: $T) -> Option<$BitFlags> {
                if (bits & !$BitFlags::all().bits()) == 0 {
                    Some($BitFlags(bits))
                } else {
                    None
                }
            }

            #[inline]
            pub const fn from_bits_truncate(bits: $T) -> $BitFlags {
                $BitFlags(bits & $BitFlags::all().bits())
            }

            /// # Safety
            #[inline]
            pub const unsafe fn from_bits_unchecked(bits: $T) -> $BitFlags {
                $BitFlags(bits)
            }

            #[inline]
            pub const fn is_empty(&self) -> bool {
                self.bits() == Self::empty().bits()
            }

            #[inline]
            pub const fn is_all(&self) -> bool {
                self.0 == Self::all().0
            }

            #[inline]
            pub const fn contains(&self, other: $BitFlags) -> bool {
                (self.0 & other.0) == other.0
            }

            #[inline]
            pub const fn intersects(&self, other: $BitFlags) -> bool {
                !$BitFlags(self.0 & other.0).is_empty()
            }

            #[inline]
            pub fn insert(&mut self, other: $BitFlags) {
                self.0 |= other.0;
            }

            #[inline]
            pub fn remove(&mut self, other: $BitFlags) {
                self.0 &= !other.0;
            }

            #[inline]
            pub fn toggle(&mut self, other: $BitFlags) {
                self.0 ^= other.0;
            }
        }

        impl ::core::default::Default for $BitFlags {
            #[inline]
            fn default() -> Self {
                Self::empty()
            }
        }

        impl ::core::ops::Not for $BitFlags {
            type Output = $BitFlags;
            #[inline]
            fn not(self) -> $BitFlags {
                $BitFlags(!self.0) & $BitFlags::all()
            }
        }

        impl ::core::ops::BitAnd for $BitFlags {
            type Output = $BitFlags;
            #[inline]
            fn bitand(self, rhs: $BitFlags) -> $BitFlags {
                $BitFlags(self.0 & rhs.0)
            }
        }

        impl ::core::ops::BitOr for $BitFlags {
            type Output = $BitFlags;
            #[inline]
            fn bitor(self, rhs: $BitFlags) -> $BitFlags {
                $BitFlags(self.0 | rhs.0)
            }
        }

        impl ::core::ops::BitXor for $BitFlags {
            type Output = $BitFlags;
            #[inline]
            fn bitxor(self, rhs: $BitFlags) -> $BitFlags {
                $BitFlags(self.0 ^ rhs.0)
            }
        }

        impl ::core::ops::BitAndAssign for $BitFlags {
            #[inline]
            fn bitand_assign(&mut self, rhs: $BitFlags) {
                self.0 &= rhs.0;
            }
        }

        impl ::core::ops::BitOrAssign for $BitFlags {
            #[inline]
            fn bitor_assign(&mut self, rhs: $BitFlags) {
                self.0 |= rhs.0;
            }
        }

        impl ::core::ops::BitXorAssign for $BitFlags {
            #[inline]
            fn bitxor_assign(&mut self, rhs: $BitFlags) {
                self.0 ^= rhs.0;
            }
        }

        impl ::core::ops::Sub for $BitFlags {
            type Output = $BitFlags;
            #[inline]
            fn sub(self, rhs: $BitFlags) -> $BitFlags {
                $BitFlags(self.0 & !rhs.0)
            }
        }

        impl ::core::ops::SubAssign for $BitFlags {
            #[inline]
            fn sub_assign(&mut self, rhs: $BitFlags) {
                self.0 &= !rhs.0;
            }
        }

        unsafe impl crate::pfs::sgx::ContiguousMemory for $BitFlags {}
    )
}

impl_bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct KeyPolicy: u16 {
        const MRENCLAVE     = 0x0001;
        const MRSIGNER      = 0x0002;
        const NOISVPRODID   = 0x0004;
        const CONFIGID      = 0x0008;
        const ISVFAMILYID   = 0x0010;
        const ISVEXTPRODID  = 0x0020;
        const KSS           = 0x0008 | 0x0010 | 0x0020;
    }
}
#[macro_export]
macro_rules! __item {
    ($i:item) => {
        $i
    };
}
#[macro_export]
macro_rules! impl_struct {
    ($($(#[$attr:meta])* pub struct $i:ident { $(pub $name:ident: $field:ty,)* })*) => ($(
        $crate::__item! {
            $(#[$attr])*
            pub struct $i { $(pub $name: $field,)* }
        }
        impl ::core::marker::Copy for $i {}
        impl ::core::clone::Clone for $i {
            fn clone(&self) -> $i { *self }
        }
        impl ::core::default::Default for $i {
            fn default() -> $i {
                $i{$($name: Default::default(),)*}
            }
        }
        unsafe impl crate::pfs::sgx::ContiguousMemory for $i {}
    )*)
}

impl KeyPolicy {
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.bits() & !Self::all().bits() == 0
    }
}

impl_struct! {
    #[repr(C)]
    #[derive(Debug, Eq, PartialEq)]
    pub struct KeyId {
        pub id: [u8; KEYID_SIZE],
    }
}

#[macro_export]
macro_rules! impl_asref_array {
    ($($t:ty;)*) => {$(
        impl ::core::convert::AsRef<[u8; ::core::mem::size_of::<$t>()]> for $t {
            #[inline]
            fn as_ref(&self) -> &[u8; ::core::mem::size_of::<$t>()] {
                unsafe { &*(self as *const _ as *const [u8; ::core::mem::size_of::<$t>()]) }
            }
        }
    )*}
}

#[macro_export]
macro_rules! impl_asmut_array {
    ($($t:ty;)*) => {$(
        impl ::core::convert::AsMut<[u8; ::core::mem::size_of::<$t>()]> for $t {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8; ::core::mem::size_of::<$t>()] {
                unsafe { &mut *(self as *mut _ as *mut [u8; ::core::mem::size_of::<$t>()]) }
            }
        }
    )*}
}

#[macro_export]
macro_rules! impl_from_array  {
    ($($t:ty;)*) => {$(
        impl ::core::convert::From<[u8; ::core::mem::size_of::<$t>()]> for $t {
            #[inline]
            fn from(array: [u8; ::core::mem::size_of::<$t>()]) -> $t {
                unsafe { ::core::mem::transmute(array) }
            }
        }

        impl ::core::convert::From<&[u8; ::core::mem::size_of::<$t>()]> for $t {
            #[inline]
            fn from(array: &[u8; ::core::mem::size_of::<$t>()]) -> $t {
                unsafe { ::core::mem::transmute(*array) }
            }
        }

        impl ::core::convert::TryFrom<&[u8]> for $t {
            type Error = ::core::array::TryFromSliceError;

            #[inline]
            fn try_from(slice: &[u8]) -> ::core::result::Result<$t, Self::Error> {
                let array: &[u8; ::core::mem::size_of::<$t>()] = slice.try_into()?;
                Ok(::core::convert::From::from(*array))
            }
        }
    )*}
}

impl_asref_array! {
    KeyId;
}
impl_asmut_array! {
    KeyId;
}
impl_from_array! {
    KeyId;
}

pub const CPUSVN_SIZE: usize = 16;

impl_struct! {
    #[repr(C)]
    #[derive(Debug, Eq, PartialEq)]
    pub struct CpuSvn {
        pub svn: [u8; CPUSVN_SIZE],
    }
}

impl_asref_array! {
    CpuSvn;
}
impl_asmut_array! {
    CpuSvn;
}
impl_from_array! {
    CpuSvn;
}

impl_bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct AttributesFlags: u64 {
        const INITTED       = 0x0000_0000_0000_0001;
        const DEBUG         = 0x0000_0000_0000_0002;
        const MODE64BIT     = 0x0000_0000_0000_0004;
        const PROVISIONKEY  = 0x0000_0000_0000_0010;
        const EINITTOKENKEY = 0x0000_0000_0000_0020;
        const CET           = 0x0000_0000_0000_0040;
        const KSS           = 0x0000_0000_0000_0080;
        const NON_SECURITY  = 0x0000_0000_0000_0004 | 0x0000_0000_0000_0010 | 0x0000_0000_0000_0020;
        const DEFAULT_MASK  = !(0x00FF_FFFF_FFFF_FFC0 | 0x0000_0000_0000_0004 | 0x0000_0000_0000_0010 | 0x0000_0000_0000_0020);
    }
}

impl_bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct MiscSelect: u32 {
        const EXINFO = 0x0000_0001;
        const CPINFO = 0x0000_0002;
    }
}

impl_struct! {
    #[repr(C)]
    #[derive(Debug, Eq, PartialEq)]
    pub struct Attributes {
        pub flags: AttributesFlags,
        pub xfrm: u64,
    }

    #[repr(C)]
    #[derive(Debug, Eq, PartialEq)]
    pub struct MiscAttribute {
        pub secs_attr: Attributes,
        pub misc_select: MiscSelect,
    }
}

impl_asref_array! {
    Attributes;
}
