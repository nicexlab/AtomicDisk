// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

use core::fmt;
pub type OsError = i32;
use crate::{impl_enum, Errno};
pub type OsResult<T = ()> = core::result::Result<T, OsError>;
pub type FsResult<T = ()> = core::result::Result<T, FsError>;
pub const ENOENT: i32 = 2;
pub const EACCES: i32 = 13;
pub const EINVAL: i32 = 22;
pub const EOPNOTSUPP: i32 = 95;
pub const ENOTSUP: i32 = EOPNOTSUPP;
pub const ENAMETOOLONG: i32 = 36;

impl_enum! {
    #[repr(u32)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub enum SgxStatus {
        Success                 = 0x0000_0000,

        Unexpected              = 0x0000_0001,      /* Unexpected error. */
        InvalidParameter        = 0x0000_0002,      /* The parameter is incorrect. */
        OutOfMemory             = 0x0000_0003,      /* Not enough memory is available to complete this operation. */
        EnclaveLost             = 0x0000_0004,      /* Enclave lost after power transition or used in child process created by linux:fork(). */
        InvalidState            = 0x0000_0005,      /* SGX API is invoked in incorrect order or state. */
        UnsupportedFeature      = 0x0000_0008,      /* Feature is not supported on this platform. */
        ThreadExit              = 0x0000_0009,      /* Enclave is exited with pthread_exit(). */
        MemoryMapFailure        = 0x0000_000A,      /* Failed to reserve memory for the enclave. */

        InvalidFunction         = 0x0000_1001,      /* The ecall/ocall index is invalid. */
        OutOfTcs                = 0x0000_1003,      /* The enclave is out of TCS. */
        EnclaveCrashed          = 0x0000_1006,      /* The enclave is crashed. */
        ECallNotAllowed         = 0x0000_1007,      /* The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization. */
        OCallNotAllowed         = 0x0000_1008,      /* The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling. */
        StackOverRun            = 0x0000_1009,      /* The enclave is running out of stack. */

        UndefinedSymbol         = 0x0000_2000,      /* The enclave image has undefined symbol. */
        InvalidEnclave          = 0x0000_2001,      /* The enclave image is not correct. */
        InvalidEcnalveId        = 0x0000_2002,      /* The enclave id is invalid. */
        InvalidSignature        = 0x0000_2003,      /* The signature is invalid. */
        NotDebugEnclave         = 0x0000_2004,      /* The enclave is signed as product enclave, and can not be created as debuggable enclave. */
        OutOfEPC                = 0x0000_2005,      /* Not enough EPC is available to load the enclave. */
        NoDevice                = 0x0000_2006,      /* Can't open SGX device. */
        MemoryMapConflict       = 0x0000_2007,      /* Page mapping failed in driver. */
        InvalidMetadata         = 0x0000_2009,      /* The metadata is incorrect. */
        DeviceBusy              = 0x0000_200C,      /* Device is busy, mostly EINIT failed. */
        InvalidVersion          = 0x0000_200D,      /* Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform. */
        ModeIncompatible        = 0x0000_200E,      /* The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS. */
        EnclaveFileAccess       = 0x0000_200F,      /* Can't open enclave file. */
        InvalidMisc             = 0x0000_2010,      /* The MiscSelct/MiscMask settings are not correct. */
        InvalidLaunchToken      = 0x0000_2011,      /* The launch token is not correct. */

        MacMismatch             = 0x0000_3001,      /* Indicates verification error for reports, sealed datas, etc. */
        InvalidAttribute        = 0x0000_3002,      /* The enclave is not authorized, e.g., requesting invalid attribute or launch key access on legacy SGX platform without FLC. */
        InvalidCpusvn           = 0x0000_3003,      /* The cpu svn is beyond platform's cpu svn value. */
        InvalidIsvsvn           = 0x0000_3004,      /* The isv svn is greater than the enclave's isv svn. */
        InvalidKeyname          = 0x0000_3005,      /* The key name is an unsupported value. */

        ServiceUnavailable      = 0x0000_4001,      /* Indicates aesm didn't respond or the requested service is not supported. */
        ServiceTimeout          = 0x0000_4002,      /* The request to aesm timed out. */
        InvalidEpidBlob         = 0x0000_4003,      /* Indicates epid blob verification error. */
        ServiceInvalidPrivilege = 0x0000_4004,      /* Enclave not authorized to run, .e.g. provisioning enclave hosted in an app without access rights to /dev/sgx_provision. */
        EpidMemoryRevoked       = 0x0000_4005,      /* The EPID group membership is revoked. */
        UpdateNeeded            = 0x0000_4006,      /* SGX needs to be updated. */
        NetworkFailure          = 0x0000_4007,      /* Network connecting or proxy setting issue is encountered. */
        InvalidAeSession        = 0x0000_4008,      /* Session is invalid or ended by server. */
        ServiceBusy             = 0x0000_400A,      /* The requested service is temporarily not availabe. */
        McNotFound              = 0x0000_400C,      /* The Monotonic Counter doesn't exist or has been invalided. */
        McNoAccess              = 0x0000_400D,      /* Caller doesn't have the access right to specified VMC. */
        McUsedUp                = 0x0000_400E,      /* Monotonic counters are used out. */
        McOverQuota             = 0x0000_400F,      /* Monotonic counters exceeds quota limitation. */
        KdfMismatch             = 0x0000_4011,      /* Key derivation function doesn't match during key exchange. */
        UnrecognizedPlatform    = 0x0000_4012,      /* EPID Provisioning failed due to platform not recognized by backend server. */
        UnsupportedConfig       = 0x0000_4013,      /* The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid. */

        NoPrivilege             = 0x0000_5002,      /* Not enough privilege to perform the operation. */

        /* SGX Protected Code Loader Error codes*/
        PclEncrypted            = 0x0000_6001,      /* trying to encrypt an already encrypted enclave. */
        PclNotEncrypted         = 0x0000_6002,      /* trying to load a plain enclave using sgx_create_encrypted_enclave. */
        PclMacMismatch          = 0x0000_6003,      /* section mac result does not match build time mac. */
        PclShaMismatch          = 0x0000_6004,      /* Unsealed key MAC does not match MAC of key hardcoded in enclave binary. */
        PclGuidMismatch         = 0x0000_6005,      /* GUID in sealed blob does not match GUID hardcoded in enclave binary. */

        /* SGX errors are only used in the file API when there is no appropriate EXXX (EINVAL, EIO etc.) error code. */
        BadStatus               = 0x0000_7001,	    /* The file is in bad status, run sgx_clearerr to try and fix it. */
        NoKeyId                 = 0x0000_7002,	    /* The Key ID field is all zeros, can't re-generate the encryption key. */
        NameMismatch            = 0x0000_7003,	    /* The current file name is different then the original file name (not allowed, substitution attack). */
        NotSgxFile              = 0x0000_7004,      /* The file is not an SGX file. */
        CantOpenRecoveryFile    = 0x0000_7005,	    /* A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned). */
        CantWriteRecoveryFile   = 0x0000_7006,      /* A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned). */
        RecoveryNeeded          = 0x0000_7007,	    /* When openeing the file, recovery is needed, but the recovery process failed. */
        FluchFailed             = 0x0000_7008,	    /* fflush operation (to disk) failed (only used when no EXXX is returned). */
        CloseFailed             = 0x0000_7009,	    /* fclose operation (to disk) failed (only used when no EXXX is returned). */

        UnsupportedAttKeyid     = 0x0000_8001,      /* platform quoting infrastructure does not support the key. */
        AttKeyCertFailed        = 0x0000_8002,      /* Failed to generate and certify the attestation key. */
        AttKeyUninitialized     = 0x0000_8003,      /* The platform quoting infrastructure does not have the attestation key available to generate quote. */
        InvaliedAttKeyCertData  = 0x0000_8004,      /* TThe data returned by the platform library's sgx_get_quote_config() is invalid. */
        INvaliedPlatfromCert    = 0x0000_8005,      /* The PCK Cert for the platform is not available. */

        EnclaveCreateInterrupted = 0x0000_F001,     /* The ioctl for enclave_create unexpectedly failed with EINTR. */
    }
}

impl SgxStatus {
    #[inline]
    pub fn is_success(&self) -> bool {
        *self == SgxStatus::Success
    }
}

impl SgxStatus {
    pub fn __description(&self) -> &'static str {
        match *self {
            SgxStatus::Success => "Success.",
            SgxStatus::Unexpected => "Unexpected error occurred.",
            SgxStatus::InvalidParameter => "The parameter is incorrect.",
            SgxStatus::OutOfMemory => "Not enough memory is available to complete this operation.",
            SgxStatus::EnclaveLost => "Enclave lost after power transition or used in child process created.",
            SgxStatus::InvalidState => "SGX API is invoked in incorrect order or state.",
            SgxStatus::UnsupportedFeature => "Feature is not supported on this platform.",
            SgxStatus::ThreadExit => "Enclave is exited with pthread_exit.",
            SgxStatus::MemoryMapFailure => "Failed to reserve memory for the enclave.",

            SgxStatus::InvalidFunction => "The ecall/ocall index is invalid.",
            SgxStatus::OutOfTcs => "The enclave is out of TCS.",
            SgxStatus::EnclaveCrashed => "The enclave is crashed.",
            SgxStatus::ECallNotAllowed => "The ECALL is not allowed at this time.",
            SgxStatus::OCallNotAllowed => "The OCALL is not allowed at this time.",
            SgxStatus::StackOverRun => "The enclave is running out of stack.",

            SgxStatus::UndefinedSymbol => "The enclave image has undefined symbol.",
            SgxStatus::InvalidEnclave => "The enclave image is not correct.",
            SgxStatus::InvalidEcnalveId => "The enclave id is invalid.",
            SgxStatus::InvalidSignature => "The signature is invalid.",
            SgxStatus::NotDebugEnclave => "The enclave can not be created as debuggable enclave.",
            SgxStatus::OutOfEPC => "Not enough EPC is available to load the enclave.",
            SgxStatus::NoDevice => "Can't open SGX device.",
            SgxStatus::MemoryMapConflict => "Page mapping failed in driver.",
            SgxStatus::InvalidMetadata => "The metadata is incorrect.",
            SgxStatus::DeviceBusy => "Device is busy, mostly EINIT failed.",
            SgxStatus::InvalidVersion => "Enclave version was invalid.",
            SgxStatus::ModeIncompatible => "The target enclave mode is incompatible with the mode of current uRTS.",
            SgxStatus::EnclaveFileAccess => "Can't open enclave file.",
            SgxStatus::InvalidMisc => "The MiscSelct/MiscMask settings are not correct.",
            SgxStatus::InvalidLaunchToken => "The launch token is not correct.",

            SgxStatus::MacMismatch => "Indicates verification error.",
            SgxStatus::InvalidAttribute => "The enclave is not authorized.",
            SgxStatus::InvalidCpusvn => "The cpu svn is beyond platform's cpu svn value.",
            SgxStatus::InvalidIsvsvn => "The isv svn is greater than the enclave's isv svn.",
            SgxStatus::InvalidKeyname => "The key name is an unsupported value.",

            SgxStatus::ServiceUnavailable => "Indicates aesm didn't response or the requested service is not supported.",
            SgxStatus::ServiceTimeout => "The request to aesm time out.",
            SgxStatus::InvalidEpidBlob => "Indicates epid blob verification error.",
            SgxStatus::ServiceInvalidPrivilege => "Enclave has no privilege to get launch token.",
            SgxStatus::EpidMemoryRevoked => "The EPID group membership is revoked.",
            SgxStatus::UpdateNeeded => "SGX needs to be updated.",
            SgxStatus::NetworkFailure => "Network connecting or proxy setting issue is encountered.",
            SgxStatus::InvalidAeSession => "Session is invalid or ended by server.",
            SgxStatus::ServiceBusy => "The requested service is temporarily not availabe.",
            SgxStatus::McNotFound => "The Monotonic Counter doesn't exist or has been invalided.",
            SgxStatus::McNoAccess => "Caller doesn't have the access right to specified VMC.",
            SgxStatus::McUsedUp => "Monotonic counters are used out.",
            SgxStatus::McOverQuota => "Monotonic counters exceeds quota limitation.",
            SgxStatus::KdfMismatch => "Key derivation function doesn't match during key exchange.",
            SgxStatus::UnrecognizedPlatform => "EPID Provisioning failed due to platform not recognized by backend server.",
            SgxStatus::UnsupportedConfig => "The config for trigging EPID Provisiong or PSE Provisiong&LTP is invalid.",
            SgxStatus::NoPrivilege => "Not enough privilege to perform the operation.",

            SgxStatus::PclEncrypted => "Trying to encrypt an already encrypted enclave.",
            SgxStatus::PclNotEncrypted => "Trying to load a plain enclave using sgx_create_encrypted_enclave.",
            SgxStatus::PclMacMismatch => "Section mac result does not match build time mac.",
            SgxStatus::PclShaMismatch => "Unsealed key MAC does not match MAC of key hardcoded in enclave binary.",
            SgxStatus::PclGuidMismatch => "GUID in sealed blob does not match GUID hardcoded in enclave binary.",

            SgxStatus::BadStatus => "The file is in bad status.",
            SgxStatus::NoKeyId => "The Key ID field is all zeros, can't regenerate the encryption key.",
            SgxStatus::NameMismatch => "The current file name is different then the original file name.",
            SgxStatus::NotSgxFile => "The file is not an SGX file.",
            SgxStatus::CantOpenRecoveryFile => "A recovery file can't be opened, so flush operation can't continue.",
            SgxStatus::CantWriteRecoveryFile => "A recovery file can't be written, so flush operation can't continue.",
            SgxStatus::RecoveryNeeded => "When openeing the file, recovery is needed, but the recovery process failed.",
            SgxStatus::FluchFailed => "fflush operation failed.",
            SgxStatus::CloseFailed => "fclose operation failed.",

            SgxStatus::UnsupportedAttKeyid => "platform quoting infrastructure does not support the key.",
            SgxStatus::AttKeyCertFailed => "Failed to generate and certify the attestation key.",
            SgxStatus::AttKeyUninitialized => "The platform quoting infrastructure does not have the attestation key available to generate quote.",
            SgxStatus::InvaliedAttKeyCertData => "The data returned by the platform library is invalid.",
            SgxStatus::INvaliedPlatfromCert => "The PCK Cert for the platform is not available.",

            SgxStatus::EnclaveCreateInterrupted => "The ioctl for enclave_create unexpectedly failed with EINTR.",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match *self {
            SgxStatus::Success => "Success.",
            SgxStatus::Unexpected => "Unexpected",
            SgxStatus::InvalidParameter => "InvalidParameter",
            SgxStatus::OutOfMemory => "OutOfMemory",
            SgxStatus::EnclaveLost => "EnclaveLost",
            SgxStatus::InvalidState => "InvalidState",
            SgxStatus::UnsupportedFeature => "UnsupportedFeature",
            SgxStatus::ThreadExit => "ThreadExit",
            SgxStatus::MemoryMapFailure => "MemoryMapFailure",

            SgxStatus::InvalidFunction => "InvalidFunction",
            SgxStatus::OutOfTcs => "OutOfTcs",
            SgxStatus::EnclaveCrashed => "EnclaveCrashed",
            SgxStatus::ECallNotAllowed => "ECallNotAllowed",
            SgxStatus::OCallNotAllowed => "OCallNotAllowed",
            SgxStatus::StackOverRun => "StackOverRun",

            SgxStatus::UndefinedSymbol => "UndefinedSymbol",
            SgxStatus::InvalidEnclave => "InvalidEnclave",
            SgxStatus::InvalidEcnalveId => "InvalidEcnalveId",
            SgxStatus::InvalidSignature => "InvalidSignature",
            SgxStatus::NotDebugEnclave => "NotDebugEnclave",
            SgxStatus::OutOfEPC => "OutOfEPC",
            SgxStatus::NoDevice => "NoDevice",
            SgxStatus::MemoryMapConflict => "MemoryMapConflict",
            SgxStatus::InvalidMetadata => "InvalidMetadata",
            SgxStatus::DeviceBusy => "DeviceBusy",
            SgxStatus::InvalidVersion => "InvalidVersion",
            SgxStatus::ModeIncompatible => "ModeIncompatible",
            SgxStatus::EnclaveFileAccess => "EnclaveFileAccess",
            SgxStatus::InvalidMisc => "InvalidMisc",
            SgxStatus::InvalidLaunchToken => "InvalidLaunchToken",

            SgxStatus::MacMismatch => "MacMismatch",
            SgxStatus::InvalidAttribute => "InvalidAttribute",
            SgxStatus::InvalidCpusvn => "InvalidCpusvn",
            SgxStatus::InvalidIsvsvn => "InvalidIsvsvn",
            SgxStatus::InvalidKeyname => "InvalidKeyname",

            SgxStatus::ServiceUnavailable => "ServiceUnavailable",
            SgxStatus::ServiceTimeout => "ServiceTimeout",
            SgxStatus::InvalidEpidBlob => "InvalidEpidBlob",
            SgxStatus::ServiceInvalidPrivilege => "ServiceInvalidPrivilege",
            SgxStatus::EpidMemoryRevoked => "EpidMemoryRevoked",
            SgxStatus::UpdateNeeded => "UpdateNeeded",
            SgxStatus::NetworkFailure => "NetworkFailure",
            SgxStatus::InvalidAeSession => "InvalidAeSession",
            SgxStatus::ServiceBusy => "ServiceBusy",
            SgxStatus::McNotFound => "McNotFound",
            SgxStatus::McNoAccess => "McNoAccess",
            SgxStatus::McUsedUp => "McUsedUp",
            SgxStatus::McOverQuota => "McOverQuota",
            SgxStatus::KdfMismatch => "KdfMismatch",
            SgxStatus::UnrecognizedPlatform => "UnrecognizedPlatform",
            SgxStatus::UnsupportedConfig => "UnsupportedConfig",
            SgxStatus::NoPrivilege => "NoPrivilege",

            SgxStatus::PclEncrypted => "PclEncrypted",
            SgxStatus::PclNotEncrypted => "PclNotEncrypted",
            SgxStatus::PclMacMismatch => "PclMacMismatch",
            SgxStatus::PclShaMismatch => "PclShaMismatch",
            SgxStatus::PclGuidMismatch => "PclGuidMismatch",

            SgxStatus::BadStatus => "BadStatus",
            SgxStatus::NoKeyId => "NoKeyId",
            SgxStatus::NameMismatch => "NameMismatch",
            SgxStatus::NotSgxFile => "NotSgxFile",
            SgxStatus::CantOpenRecoveryFile => "CantOpenRecoveryFile",
            SgxStatus::CantWriteRecoveryFile => "CantWriteRecoveryFile",
            SgxStatus::RecoveryNeeded => "RecoveryNeeded",
            SgxStatus::FluchFailed => "FluchFailed",
            SgxStatus::CloseFailed => "CloseFailed",

            SgxStatus::UnsupportedAttKeyid => "UnsupportedAttKeyid",
            SgxStatus::AttKeyCertFailed => "AttKeyCertFailed",
            SgxStatus::AttKeyUninitialized => "AttKeyUninitialized",
            SgxStatus::InvaliedAttKeyCertData => "InvaliedAttKeyCertData",
            SgxStatus::INvaliedPlatfromCert => "INvaliedPlatfromCert",

            SgxStatus::EnclaveCreateInterrupted => "EnclaveCreateInterrupted",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsError {
    SgxError(SgxStatus),
    OsError(i32),
    Errno(crate::error::Error),
}

impl FsError {
    #[inline]
    pub fn from_sgx_error(errno: SgxStatus) -> Self {
        FsError::SgxError(errno)
    }

    #[inline]
    pub fn from_os_error(errno: i32) -> Self {
        FsError::OsError(errno)
    }

    #[inline]
    pub fn equal_to_sgx_error(&self, other: SgxStatus) -> bool {
        matches!(self, FsError::SgxError(e) if *e == other)
    }

    #[allow(dead_code)]
    #[inline]
    pub fn equal_to_os_error(&self, other: i32) -> bool {
        matches!(self, FsError::OsError(e) if *e == other)
    }

    #[inline]
    pub fn is_success(&self) -> bool {
        match self {
            Self::SgxError(status) => status.is_success(),
            Self::OsError(errno) => *errno == 0,
            Self::Errno(_) => false,
        }
    }

    // pub fn set_errno(&self) {
    //     extern "C" {
    //         #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    //         fn errno_location() -> *mut i32;
    //     }
    //     let e = match self {
    //         Self::SgxError(status) => *status as i32,
    //         Self::OsError(errno) => *errno,
    //         Self::Errno(errno) => errno.errno() as i32,
    //     };
    //     unsafe { *errno_location() = e }
    // }

    #[allow(dead_code)]
    pub fn to_errno(self) -> crate::Error {
        match self {
            Self::SgxError(status) => crate::Error::with_msg(Errno::SgxError, status.as_str()),
            Self::OsError(errno) => crate::Error::from(errno),
            Self::Errno(errno) => crate::Error::from(errno),
        }
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SgxError(status) => write!(fmt, "sgx error {}", status.as_str()),
            Self::OsError(errno) => write!(fmt, "os error {}", errno),
            Self::Errno(errno) => write!(fmt, "errno {}", errno),
        }
    }
}

impl From<SgxStatus> for FsError {
    fn from(errno: SgxStatus) -> FsError {
        FsError::from_sgx_error(errno)
    }
}

#[macro_export]
macro_rules! esgx {
    ($status:expr) => {
        $crate::sys::error::FsError::from_sgx_error($status)
    };
}

#[macro_export]
macro_rules! eos {
    ($errno:expr) => {
        $crate::pfs::sys::error::FsError::from_os_error($errno)
    };
}
