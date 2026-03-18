
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha512};
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};
use zeroize::Zeroize;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

pub const CUSTOM_EXTENSION: &str = "plock";
pub const LEGACY_CUSTOM_EXTENSION: &str = "rvault";

fn is_vault_extension(extension: &str) -> bool {
    extension.eq_ignore_ascii_case(CUSTOM_EXTENSION)
        || extension.eq_ignore_ascii_case(LEGACY_CUSTOM_EXTENSION)
}

const MAGIC: [u8; 4] = *b"RVLT";
const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const VERSION_V3: u8 = 3;
const VERSION_V4: u8 = 4;

const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 8;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FEK_LEN: usize = 32;
const KEYFILE_DIGEST_LEN: usize = 64;
const KEYFILE_RANDOM_LEN: usize = 64;
const WRAPPED_FEK_LEN: usize = FEK_LEN + TAG_LEN;
const WRAPPED_FEK_V3_MAX_LEN: usize = WRAPPED_FEK_LEN + TAG_LEN;
const WRAPPED_KEY_MATERIAL_V4_PLAINTEXT_LEN: usize = FEK_LEN + 8;
const WRAPPED_KEY_MATERIAL_V4_LEN: usize = WRAPPED_KEY_MATERIAL_V4_PLAINTEXT_LEN + TAG_LEN;

const FLAG_FINAL: u8 = 0x01;
const HEADER_FLAG_KEYFILE_REQUIRED: u8 = 0x01;

const KDF_ID_ARGON2ID: u8 = 1;
const WRAP_ALG_ID_AES256GCM_HKDF_SHA512: u8 = 1;
const WRAP_ALG_ID_AES256GCM_LAYERED_KEK: u8 = 2;
const CONTENT_ALG_ID_AES256_GCM: u8 = 1;

const LEGACY_HEADER_LEN: usize = 45;
const HEADER_V2_LEN: usize = 136;
const HEADER_V3_LEN: usize = 166;
const HEADER_V4_LEN: usize = 150;
const WRAPPED_FEK_OFFSET: usize = 74;
const WRAPPED_FEK_V3_OFFSET: usize = 102;
const WRAPPED_KEY_MATERIAL_V4_OFFSET: usize = 94;

const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
const MAX_KEYFILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const MIN_ARGON_MEMORY_KIB: u32 = 64 * 1024;
const MAX_ARGON_MEMORY_KIB: u32 = 524_288;
const MAX_ARGON_ITERATIONS: u32 = 10;
const MAX_ARGON_LANES: u32 = 8;
const TEMP_FILE_PREFIX: &str = ".plock-";
const TEMP_KEYFILE_PREFIX: &str = ".plock-key-";
const TEMP_FILE_SUFFIX: &str = ".tmp";
const TEMP_TRACKING_FILE_NAME: &str = "pillowlock-active-tempfiles.txt";

#[derive(Debug, Clone, Copy)]
pub struct VaultConfig {
    pub chunk_size: usize,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_lanes: u32,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024,
            argon_memory_kib: 262_144,
            argon_iterations: 3,
            argon_lanes: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptOptions {
    pub config: VaultConfig,
    pub keyfile: Option<PathBuf>,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            config: VaultConfig::default(),
            keyfile: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DecryptOptions {
    pub keyfile: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSummary {
    pub version: u8,
    pub cipher: &'static str,
    pub kdf: &'static str,
    pub key_wrap: &'static str,
    pub keyfile_required: bool,
    pub chunk_size: u32,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_lanes: u32,
    pub supports_rewrap: bool,
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("input file does not exist or is not a regular file")]
    InvalidInputPath,
    #[error("keyfile does not exist or is not a regular file")]
    InvalidKeyfilePath,
    #[error("keyfile is too large: {0} bytes")]
    KeyfileTooLarge(u64),
    #[error("output file already exists: {0}")]
    OutputExists(String),
    #[error("password cannot be empty")]
    EmptyPassword,
    #[error("keyfile is required for this encrypted file")]
    KeyfileRequired,
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("encrypted file format is invalid or truncated")]
    InvalidFormat,
    #[error("unsupported encrypted file version: {0}")]
    UnsupportedVersion(u8),
    #[error("key rotation is not supported for encrypted file version: {0}")]
    UnsupportedRewrapVersion(u8),
    #[error("this v4 vault was created with a legacy layout that cannot be rewrapped in place")]
    UnsupportedRewrapLayout,
    #[error("unsupported algorithm identifiers in file header")]
    UnsupportedAlgorithms,
    #[error("authentication failed: wrong password, wrong keyfile, or file was modified")]
    AuthenticationFailed,
    #[error("operation was cancelled")]
    Cancelled,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("key derivation error: {0}")]
    KeyDerivation(String),
    #[error("key expansion failed")]
    KeyExpansion,
    #[error("internal encryption failure")]
    EncryptionFailure,
    #[error("output path must have an existing parent directory")]
    NoParentDirectory,
    #[error("input and output paths must differ")]
    SameInputAndOutput,
    #[error("too many chunks for this file")]
    TooManyChunks,
    #[error("file is too large for this container format")]
    FileTooLarge,
}

impl From<argon2::Error> for VaultError {
    fn from(value: argon2::Error) -> Self {
        Self::KeyDerivation(value.to_string())
    }
}

#[derive(Debug, Clone)]
struct HeaderV2 {
    flags: u8,
    plaintext_size: u64,
    chunk_size: u32,
    argon_memory_kib: u32,
    argon_iterations: u32,
    argon_lanes: u32,
    kdf_salt: [u8; SALT_LEN],
    content_nonce_prefix: [u8; NONCE_PREFIX_LEN],
    wrapped_fek_nonce: [u8; NONCE_LEN],
    wrapped_fek: [u8; WRAPPED_FEK_LEN],
}

impl HeaderV2 {
    fn requires_keyfile(&self) -> bool {
        (self.flags & HEADER_FLAG_KEYFILE_REQUIRED) != 0
    }

    fn encode(&self) -> [u8; HEADER_V2_LEN] {
        let mut out = [0u8; HEADER_V2_LEN];
        let mut offset = 0usize;

        out[offset..offset + 4].copy_from_slice(&MAGIC);
        offset += 4;
        out[offset] = VERSION_V2;
        offset += 1;
        out[offset] = self.flags;
        offset += 1;
        out[offset] = KDF_ID_ARGON2ID;
        offset += 1;
        out[offset] = WRAP_ALG_ID_AES256GCM_HKDF_SHA512;
        offset += 1;
        out[offset] = CONTENT_ALG_ID_AES256_GCM;
        offset += 1;

        offset += 3; // reserved for future agility fields

        out[offset..offset + 8].copy_from_slice(&self.plaintext_size.to_le_bytes());
        offset += 8;
        out[offset..offset + 4].copy_from_slice(&self.chunk_size.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_memory_kib.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_iterations.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_lanes.to_le_bytes());
        offset += 4;
        out[offset..offset + SALT_LEN].copy_from_slice(&self.kdf_salt);
        offset += SALT_LEN;
        out[offset..offset + NONCE_PREFIX_LEN].copy_from_slice(&self.content_nonce_prefix);
        offset += NONCE_PREFIX_LEN;
        out[offset..offset + NONCE_LEN].copy_from_slice(&self.wrapped_fek_nonce);
        offset += NONCE_LEN;
        out[offset..offset + 2].copy_from_slice(&(WRAPPED_FEK_LEN as u16).to_le_bytes());
        offset += 2;
        out[offset..offset + WRAPPED_FEK_LEN].copy_from_slice(&self.wrapped_fek);

        out
    }

    fn wrap_aad(&self) -> [u8; HEADER_V2_LEN] {
        let mut bytes = self.encode();
        bytes[WRAPPED_FEK_OFFSET..WRAPPED_FEK_OFFSET + WRAPPED_FEK_LEN].fill(0);
        bytes
    }

    fn decode(encoded: &[u8; HEADER_V2_LEN]) -> Result<Self, VaultError> {
        if &encoded[0..4] != &MAGIC {
            return Err(VaultError::InvalidFormat);
        }
        if encoded[4] != VERSION_V2 {
            return Err(VaultError::UnsupportedVersion(encoded[4]));
        }

        let flags = encoded[5];
        if flags & !HEADER_FLAG_KEYFILE_REQUIRED != 0 {
            return Err(VaultError::InvalidFormat);
        }
        if encoded[6] != KDF_ID_ARGON2ID
            || encoded[7] != WRAP_ALG_ID_AES256GCM_HKDF_SHA512
            || encoded[8] != CONTENT_ALG_ID_AES256_GCM
        {
            return Err(VaultError::UnsupportedAlgorithms);
        }

        let mut offset = 12usize;
        let plaintext_size = u64::from_le_bytes(
            encoded[offset..offset + 8]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 8;

        let chunk_size = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_memory_kib = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_iterations = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_lanes = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;

        if chunk_size == 0 || chunk_size as usize > MAX_CHUNK_SIZE {
            return Err(VaultError::InvalidFormat);
        }
        if !(MIN_ARGON_MEMORY_KIB..=MAX_ARGON_MEMORY_KIB).contains(&argon_memory_kib) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_ITERATIONS).contains(&argon_iterations) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_LANES).contains(&argon_lanes) {
            return Err(VaultError::InvalidFormat);
        }

        let mut kdf_salt = [0u8; SALT_LEN];
        kdf_salt.copy_from_slice(&encoded[offset..offset + SALT_LEN]);
        offset += SALT_LEN;

        let mut content_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        content_nonce_prefix.copy_from_slice(&encoded[offset..offset + NONCE_PREFIX_LEN]);
        offset += NONCE_PREFIX_LEN;

        let mut wrapped_fek_nonce = [0u8; NONCE_LEN];
        wrapped_fek_nonce.copy_from_slice(&encoded[offset..offset + NONCE_LEN]);
        offset += NONCE_LEN;

        let wrapped_fek_len = u16::from_le_bytes(
            encoded[offset..offset + 2]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        ) as usize;
        offset += 2;

        if wrapped_fek_len != WRAPPED_FEK_LEN {
            return Err(VaultError::InvalidFormat);
        }

        let mut wrapped_fek = [0u8; WRAPPED_FEK_LEN];
        wrapped_fek.copy_from_slice(&encoded[offset..offset + WRAPPED_FEK_LEN]);

        Ok(Self {
            flags,
            plaintext_size,
            chunk_size,
            argon_memory_kib,
            argon_iterations,
            argon_lanes,
            kdf_salt,
            content_nonce_prefix,
            wrapped_fek_nonce,
            wrapped_fek,
        })
    }
}

#[derive(Debug, Clone)]
struct HeaderV3 {
    flags: u8,
    plaintext_size: u64,
    chunk_size: u32,
    argon_memory_kib: u32,
    argon_iterations: u32,
    argon_lanes: u32,
    password_kdf_salt: [u8; SALT_LEN],
    content_nonce_prefix: [u8; NONCE_PREFIX_LEN],
    password_wrap_nonce: [u8; NONCE_LEN],
    keyfile_kdf_salt: [u8; SALT_LEN],
    keyfile_wrap_nonce: [u8; NONCE_LEN],
    wrapped_fek_len: u16,
    wrapped_fek: [u8; WRAPPED_FEK_V3_MAX_LEN],
}

impl HeaderV3 {
    #[cfg(test)]
    fn new(plaintext_size: u64, config: &VaultConfig, use_keyfile: bool) -> Result<Self, VaultError> {
        validate_config(config)?;

        let mut password_kdf_salt = [0u8; SALT_LEN];
        let mut content_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        let mut password_wrap_nonce = [0u8; NONCE_LEN];
        let mut keyfile_kdf_salt = [0u8; SALT_LEN];
        let mut keyfile_wrap_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut password_kdf_salt);
        OsRng.fill_bytes(&mut content_nonce_prefix);
        OsRng.fill_bytes(&mut password_wrap_nonce);
        OsRng.fill_bytes(&mut keyfile_kdf_salt);
        OsRng.fill_bytes(&mut keyfile_wrap_nonce);

        Ok(Self {
            flags: if use_keyfile {
                HEADER_FLAG_KEYFILE_REQUIRED
            } else {
                0
            },
            plaintext_size,
            chunk_size: config.chunk_size as u32,
            argon_memory_kib: config.argon_memory_kib,
            argon_iterations: config.argon_iterations,
            argon_lanes: config.argon_lanes,
            password_kdf_salt,
            content_nonce_prefix,
            password_wrap_nonce,
            keyfile_kdf_salt,
            keyfile_wrap_nonce,
            wrapped_fek_len: if use_keyfile {
                WRAPPED_FEK_V3_MAX_LEN as u16
            } else {
                WRAPPED_FEK_LEN as u16
            },
            wrapped_fek: [0u8; WRAPPED_FEK_V3_MAX_LEN],
        })
    }

    fn requires_keyfile(&self) -> bool {
        (self.flags & HEADER_FLAG_KEYFILE_REQUIRED) != 0
    }

    #[cfg(test)]
    fn expected_wrapped_fek_len(&self) -> usize {
        if self.requires_keyfile() {
            WRAPPED_FEK_V3_MAX_LEN
        } else {
            WRAPPED_FEK_LEN
        }
    }

    #[cfg(test)]
    fn set_wrapped_fek(&mut self, wrapped_fek: &[u8]) -> Result<(), VaultError> {
        if wrapped_fek.len() != self.expected_wrapped_fek_len() {
            return Err(VaultError::EncryptionFailure);
        }
        self.wrapped_fek.fill(0);
        self.wrapped_fek_len = wrapped_fek.len() as u16;
        self.wrapped_fek[..wrapped_fek.len()].copy_from_slice(wrapped_fek);
        Ok(())
    }

    fn wrapped_fek_bytes(&self) -> &[u8] {
        &self.wrapped_fek[..self.wrapped_fek_len as usize]
    }

    fn encode(&self) -> [u8; HEADER_V3_LEN] {
        let mut out = [0u8; HEADER_V3_LEN];
        let mut offset = 0usize;

        out[offset..offset + 4].copy_from_slice(&MAGIC);
        offset += 4;
        out[offset] = VERSION_V3;
        offset += 1;
        out[offset] = self.flags;
        offset += 1;
        out[offset] = KDF_ID_ARGON2ID;
        offset += 1;
        out[offset] = WRAP_ALG_ID_AES256GCM_LAYERED_KEK;
        offset += 1;
        out[offset] = CONTENT_ALG_ID_AES256_GCM;
        offset += 1;

        offset += 3; // reserved for future agility fields

        out[offset..offset + 8].copy_from_slice(&self.plaintext_size.to_le_bytes());
        offset += 8;
        out[offset..offset + 4].copy_from_slice(&self.chunk_size.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_memory_kib.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_iterations.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_lanes.to_le_bytes());
        offset += 4;
        out[offset..offset + SALT_LEN].copy_from_slice(&self.password_kdf_salt);
        offset += SALT_LEN;
        out[offset..offset + NONCE_PREFIX_LEN].copy_from_slice(&self.content_nonce_prefix);
        offset += NONCE_PREFIX_LEN;
        out[offset..offset + NONCE_LEN].copy_from_slice(&self.password_wrap_nonce);
        offset += NONCE_LEN;
        out[offset..offset + SALT_LEN].copy_from_slice(&self.keyfile_kdf_salt);
        offset += SALT_LEN;
        out[offset..offset + NONCE_LEN].copy_from_slice(&self.keyfile_wrap_nonce);
        offset += NONCE_LEN;
        out[offset..offset + 2].copy_from_slice(&self.wrapped_fek_len.to_le_bytes());
        offset += 2;
        out[offset..offset + WRAPPED_FEK_V3_MAX_LEN].copy_from_slice(&self.wrapped_fek);

        out
    }

    fn wrap_aad(&self) -> [u8; HEADER_V3_LEN] {
        let mut bytes = self.encode();
        bytes[WRAPPED_FEK_V3_OFFSET..WRAPPED_FEK_V3_OFFSET + WRAPPED_FEK_V3_MAX_LEN].fill(0);
        bytes
    }

    fn decode(encoded: &[u8; HEADER_V3_LEN]) -> Result<Self, VaultError> {
        if &encoded[0..4] != &MAGIC {
            return Err(VaultError::InvalidFormat);
        }
        if encoded[4] != VERSION_V3 {
            return Err(VaultError::UnsupportedVersion(encoded[4]));
        }

        let flags = encoded[5];
        if flags & !HEADER_FLAG_KEYFILE_REQUIRED != 0 {
            return Err(VaultError::InvalidFormat);
        }
        if encoded[6] != KDF_ID_ARGON2ID
            || encoded[7] != WRAP_ALG_ID_AES256GCM_LAYERED_KEK
            || encoded[8] != CONTENT_ALG_ID_AES256_GCM
        {
            return Err(VaultError::UnsupportedAlgorithms);
        }

        let mut offset = 12usize;
        let plaintext_size = u64::from_le_bytes(
            encoded[offset..offset + 8]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 8;

        let chunk_size = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_memory_kib = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_iterations = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_lanes = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;

        if chunk_size == 0 || chunk_size as usize > MAX_CHUNK_SIZE {
            return Err(VaultError::InvalidFormat);
        }
        if !(MIN_ARGON_MEMORY_KIB..=MAX_ARGON_MEMORY_KIB).contains(&argon_memory_kib) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_ITERATIONS).contains(&argon_iterations) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_LANES).contains(&argon_lanes) {
            return Err(VaultError::InvalidFormat);
        }

        let mut password_kdf_salt = [0u8; SALT_LEN];
        password_kdf_salt.copy_from_slice(&encoded[offset..offset + SALT_LEN]);
        offset += SALT_LEN;

        let mut content_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        content_nonce_prefix.copy_from_slice(&encoded[offset..offset + NONCE_PREFIX_LEN]);
        offset += NONCE_PREFIX_LEN;

        let mut password_wrap_nonce = [0u8; NONCE_LEN];
        password_wrap_nonce.copy_from_slice(&encoded[offset..offset + NONCE_LEN]);
        offset += NONCE_LEN;

        let mut keyfile_kdf_salt = [0u8; SALT_LEN];
        keyfile_kdf_salt.copy_from_slice(&encoded[offset..offset + SALT_LEN]);
        offset += SALT_LEN;

        let mut keyfile_wrap_nonce = [0u8; NONCE_LEN];
        keyfile_wrap_nonce.copy_from_slice(&encoded[offset..offset + NONCE_LEN]);
        offset += NONCE_LEN;

        let wrapped_fek_len = u16::from_le_bytes(
            encoded[offset..offset + 2]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 2;

        let expected_wrapped_fek_len = if (flags & HEADER_FLAG_KEYFILE_REQUIRED) != 0 {
            WRAPPED_FEK_V3_MAX_LEN
        } else {
            WRAPPED_FEK_LEN
        };
        if wrapped_fek_len as usize != expected_wrapped_fek_len {
            return Err(VaultError::InvalidFormat);
        }

        let mut wrapped_fek = [0u8; WRAPPED_FEK_V3_MAX_LEN];
        wrapped_fek.copy_from_slice(&encoded[offset..offset + WRAPPED_FEK_V3_MAX_LEN]);

        Ok(Self {
            flags,
            plaintext_size,
            chunk_size,
            argon_memory_kib,
            argon_iterations,
            argon_lanes,
            password_kdf_salt,
            content_nonce_prefix,
            password_wrap_nonce,
            keyfile_kdf_salt,
            keyfile_wrap_nonce,
            wrapped_fek_len,
            wrapped_fek,
        })
    }
}

#[derive(Debug, Clone)]
struct HeaderV4 {
    flags: u8,
    chunk_size: u32,
    argon_memory_kib: u32,
    argon_iterations: u32,
    argon_lanes: u32,
    password_kdf_salt: [u8; SALT_LEN],
    content_nonce_prefix: [u8; NONCE_PREFIX_LEN],
    wrapping_nonce: [u8; NONCE_LEN],
    key_binding_salt: [u8; SALT_LEN],
    key_binding_nonce: [u8; NONCE_LEN],
    wrapped_key_material_len: u16,
    wrapped_key_material: [u8; WRAPPED_KEY_MATERIAL_V4_LEN],
}

impl HeaderV4 {
    fn new(config: &VaultConfig, use_keyfile: bool) -> Result<Self, VaultError> {
        validate_config(config)?;

        let mut password_kdf_salt = [0u8; SALT_LEN];
        let mut content_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        let mut wrapping_nonce = [0u8; NONCE_LEN];
        let mut key_binding_salt = [0u8; SALT_LEN];
        let mut key_binding_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut password_kdf_salt);
        OsRng.fill_bytes(&mut content_nonce_prefix);
        OsRng.fill_bytes(&mut wrapping_nonce);
        OsRng.fill_bytes(&mut key_binding_salt);
        OsRng.fill_bytes(&mut key_binding_nonce);

        Ok(Self {
            flags: if use_keyfile {
                HEADER_FLAG_KEYFILE_REQUIRED
            } else {
                0
            },
            chunk_size: config.chunk_size as u32,
            argon_memory_kib: config.argon_memory_kib,
            argon_iterations: config.argon_iterations,
            argon_lanes: config.argon_lanes,
            password_kdf_salt,
            content_nonce_prefix,
            wrapping_nonce,
            key_binding_salt,
            key_binding_nonce,
            wrapped_key_material_len: WRAPPED_KEY_MATERIAL_V4_LEN as u16,
            wrapped_key_material: [0u8; WRAPPED_KEY_MATERIAL_V4_LEN],
        })
    }

    fn requires_keyfile(&self) -> bool {
        (self.flags & HEADER_FLAG_KEYFILE_REQUIRED) != 0
    }

    fn key_binding_salt_bytes(&self) -> [u8; SALT_LEN + NONCE_LEN] {
        let mut out = [0u8; SALT_LEN + NONCE_LEN];
        out[..SALT_LEN].copy_from_slice(&self.key_binding_salt);
        out[SALT_LEN..].copy_from_slice(&self.key_binding_nonce);
        out
    }

    fn set_wrapped_key_material(&mut self, wrapped_key_material: &[u8]) -> Result<(), VaultError> {
        if wrapped_key_material.len() != WRAPPED_KEY_MATERIAL_V4_LEN {
            return Err(VaultError::EncryptionFailure);
        }
        self.wrapped_key_material.fill(0);
        self.wrapped_key_material_len = wrapped_key_material.len() as u16;
        self.wrapped_key_material[..wrapped_key_material.len()].copy_from_slice(wrapped_key_material);
        Ok(())
    }

    fn encode(&self) -> [u8; HEADER_V4_LEN] {
        let mut out = [0u8; HEADER_V4_LEN];
        let mut offset = 0usize;

        out[offset..offset + 4].copy_from_slice(&MAGIC);
        offset += 4;
        out[offset] = VERSION_V4;
        offset += 1;
        out[offset] = self.flags;
        offset += 1;
        out[offset] = KDF_ID_ARGON2ID;
        offset += 1;
        out[offset] = WRAP_ALG_ID_AES256GCM_LAYERED_KEK;
        offset += 1;
        out[offset] = CONTENT_ALG_ID_AES256_GCM;
        offset += 1;

        offset += 3;

        out[offset..offset + 4].copy_from_slice(&self.chunk_size.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_memory_kib.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_iterations.to_le_bytes());
        offset += 4;
        out[offset..offset + 4].copy_from_slice(&self.argon_lanes.to_le_bytes());
        offset += 4;
        out[offset..offset + SALT_LEN].copy_from_slice(&self.password_kdf_salt);
        offset += SALT_LEN;
        out[offset..offset + NONCE_PREFIX_LEN].copy_from_slice(&self.content_nonce_prefix);
        offset += NONCE_PREFIX_LEN;
        out[offset..offset + NONCE_LEN].copy_from_slice(&self.wrapping_nonce);
        offset += NONCE_LEN;
        out[offset..offset + SALT_LEN].copy_from_slice(&self.key_binding_salt);
        offset += SALT_LEN;
        out[offset..offset + NONCE_LEN].copy_from_slice(&self.key_binding_nonce);
        offset += NONCE_LEN;
        out[offset..offset + 2].copy_from_slice(&self.wrapped_key_material_len.to_le_bytes());
        offset += 2;
        out[offset..offset + WRAPPED_KEY_MATERIAL_V4_LEN].copy_from_slice(&self.wrapped_key_material);

        out
    }

    fn wrap_aad(&self) -> [u8; HEADER_V4_LEN] {
        let mut bytes = self.encode();
        bytes[WRAPPED_KEY_MATERIAL_V4_OFFSET..WRAPPED_KEY_MATERIAL_V4_OFFSET + WRAPPED_KEY_MATERIAL_V4_LEN]
            .fill(0);
        bytes
    }

    fn content_aad(&self) -> [u8; 21] {
        let mut aad = [0u8; 21];
        aad[0..4].copy_from_slice(&MAGIC);
        aad[4] = VERSION_V4;
        aad[5] = CONTENT_ALG_ID_AES256_GCM;
        aad[6..10].copy_from_slice(&self.chunk_size.to_le_bytes());
        aad[10..18].copy_from_slice(&self.content_nonce_prefix);
        aad[18..21].copy_from_slice(b"v4c");
        aad
    }

    fn decode(encoded: &[u8; HEADER_V4_LEN]) -> Result<Self, VaultError> {
        if &encoded[0..4] != &MAGIC {
            return Err(VaultError::InvalidFormat);
        }
        if encoded[4] != VERSION_V4 {
            return Err(VaultError::UnsupportedVersion(encoded[4]));
        }

        let flags = encoded[5];
        if flags & !HEADER_FLAG_KEYFILE_REQUIRED != 0 {
            return Err(VaultError::InvalidFormat);
        }
        if encoded[6] != KDF_ID_ARGON2ID
            || encoded[7] != WRAP_ALG_ID_AES256GCM_LAYERED_KEK
            || encoded[8] != CONTENT_ALG_ID_AES256_GCM
        {
            return Err(VaultError::UnsupportedAlgorithms);
        }

        let mut offset = 12usize;
        let chunk_size = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_memory_kib = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_iterations = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_lanes = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;

        if chunk_size == 0 || chunk_size as usize > MAX_CHUNK_SIZE {
            return Err(VaultError::InvalidFormat);
        }
        if !(MIN_ARGON_MEMORY_KIB..=MAX_ARGON_MEMORY_KIB).contains(&argon_memory_kib) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_ITERATIONS).contains(&argon_iterations) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_LANES).contains(&argon_lanes) {
            return Err(VaultError::InvalidFormat);
        }

        let mut password_kdf_salt = [0u8; SALT_LEN];
        password_kdf_salt.copy_from_slice(&encoded[offset..offset + SALT_LEN]);
        offset += SALT_LEN;

        let mut content_nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        content_nonce_prefix.copy_from_slice(&encoded[offset..offset + NONCE_PREFIX_LEN]);
        offset += NONCE_PREFIX_LEN;

        let mut wrapping_nonce = [0u8; NONCE_LEN];
        wrapping_nonce.copy_from_slice(&encoded[offset..offset + NONCE_LEN]);
        offset += NONCE_LEN;

        let mut key_binding_salt = [0u8; SALT_LEN];
        key_binding_salt.copy_from_slice(&encoded[offset..offset + SALT_LEN]);
        offset += SALT_LEN;

        let mut key_binding_nonce = [0u8; NONCE_LEN];
        key_binding_nonce.copy_from_slice(&encoded[offset..offset + NONCE_LEN]);
        offset += NONCE_LEN;

        let wrapped_key_material_len = u16::from_le_bytes(
            encoded[offset..offset + 2]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 2;

        if wrapped_key_material_len as usize != WRAPPED_KEY_MATERIAL_V4_LEN {
            return Err(VaultError::InvalidFormat);
        }

        let mut wrapped_key_material = [0u8; WRAPPED_KEY_MATERIAL_V4_LEN];
        wrapped_key_material.copy_from_slice(&encoded[offset..offset + WRAPPED_KEY_MATERIAL_V4_LEN]);

        Ok(Self {
            flags,
            chunk_size,
            argon_memory_kib,
            argon_iterations,
            argon_lanes,
            password_kdf_salt,
            content_nonce_prefix,
            wrapping_nonce,
            key_binding_salt,
            key_binding_nonce,
            wrapped_key_material_len,
            wrapped_key_material,
        })
    }
}

#[derive(Debug, Clone)]
struct HeaderV1 {
    salt: [u8; SALT_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    chunk_size: u32,
    argon_memory_kib: u32,
    argon_iterations: u32,
    argon_lanes: u32,
}

impl HeaderV1 {
    fn decode(encoded: &[u8; LEGACY_HEADER_LEN]) -> Result<Self, VaultError> {
        if &encoded[0..4] != &MAGIC || encoded[4] != VERSION_V1 {
            return Err(VaultError::InvalidFormat);
        }

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&encoded[5..5 + SALT_LEN]);

        let nonce_start = 5 + SALT_LEN;
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&encoded[nonce_start..nonce_start + NONCE_PREFIX_LEN]);

        let mut offset = nonce_start + NONCE_PREFIX_LEN;
        let chunk_size = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_memory_kib = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_iterations = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );
        offset += 4;
        let argon_lanes = u32::from_le_bytes(
            encoded[offset..offset + 4]
                .try_into()
                .map_err(|_| VaultError::InvalidFormat)?,
        );

        if chunk_size == 0 || chunk_size as usize > MAX_CHUNK_SIZE {
            return Err(VaultError::InvalidFormat);
        }
        if !(MIN_ARGON_MEMORY_KIB..=MAX_ARGON_MEMORY_KIB).contains(&argon_memory_kib) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_ITERATIONS).contains(&argon_iterations) {
            return Err(VaultError::InvalidFormat);
        }
        if !(1..=MAX_ARGON_LANES).contains(&argon_lanes) {
            return Err(VaultError::InvalidFormat);
        }

        Ok(Self {
            salt,
            nonce_prefix,
            chunk_size,
            argon_memory_kib,
            argon_iterations,
            argon_lanes,
        })
    }
}

pub fn default_encrypted_output_path(input: &Path) -> PathBuf {
    let mut name: OsString = input.as_os_str().to_os_string();
    name.push(format!(".{CUSTOM_EXTENSION}"));
    PathBuf::from(name)
}

pub fn default_decrypted_output_path(input: &Path) -> PathBuf {
    let is_vault = input
        .extension()
        .and_then(|ext| ext.to_str())
        .map(is_vault_extension)
        .unwrap_or(false);

    if is_vault {
        input.with_extension("")
    } else {
        let filename = input
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("decrypted_output");
        input.with_file_name(format!("{filename}.decrypted"))
    }
}

pub fn generate_keyfile(output: &Path) -> Result<(), VaultError> {
    let parent = resolve_parent_directory(output)?;
    if output.exists() {
        return Err(VaultError::OutputExists(output.display().to_string()));
    }

    let mut temp = create_tracked_tempfile(&parent, TEMP_KEYFILE_PREFIX)?;

    let mut key_material = [0u8; KEYFILE_RANDOM_LEN];
    OsRng.fill_bytes(&mut key_material);

    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        writer.write_all(&key_material)?;
        writer.flush()?;
    }
    temp.as_file_mut().sync_all()?;
    key_material.zeroize();

    persist_tempfile_noclobber(temp, output)?;
    Ok(())
}

pub fn encrypt_file(
    input: &Path,
    output: &Path,
    password: &str,
    options: &EncryptOptions,
) -> Result<(), VaultError> {
    encrypt_file_v4(input, output, password, options, None)
}

pub fn encrypt_file_with_cancel(
    input: &Path,
    output: &Path,
    password: &str,
    options: &EncryptOptions,
    cancel_flag: &AtomicBool,
) -> Result<(), VaultError> {
    encrypt_file_v4(input, output, password, options, Some(cancel_flag))
}

fn encrypt_file_v4(
    input: &Path,
    output: &Path,
    password: &str,
    options: &EncryptOptions,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    ensure_file_input(input)?;
    ensure_output_target(input, output)?;
    check_cancelled(cancel_flag)?;

    let input_size = fs::metadata(input)?.len();
    let mut header = HeaderV4::new(&options.config, options.keyfile.is_some())?;

    let mut wrapping_key = derive_wrapping_key_v4(password, options.keyfile.as_deref(), &header)?;
    let wrapping_cipher =
        Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| VaultError::EncryptionFailure)?;

    let mut fek = [0u8; FEK_LEN];
    OsRng.fill_bytes(&mut fek);
    let mut wrapped_plaintext = [0u8; WRAPPED_KEY_MATERIAL_V4_PLAINTEXT_LEN];
    wrapped_plaintext[..8].copy_from_slice(&input_size.to_le_bytes());
    wrapped_plaintext[8..].copy_from_slice(&fek);

    let wrap_aad = header.wrap_aad();
    let mut wrapped_key_material = wrapping_cipher
        .encrypt(
            Nonce::from_slice(&header.wrapping_nonce),
            Payload {
                msg: &wrapped_plaintext,
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::EncryptionFailure)?;
    header.set_wrapped_key_material(&wrapped_key_material)?;

    let header_bytes = header.encode();
    let content_aad = header.content_aad();

    let content_cipher = Aes256Gcm::new_from_slice(&fek).map_err(|_| VaultError::EncryptionFailure)?;

    let parent = resolve_parent_directory(output)?;
    let input_file = File::open(input)?;
    let mut reader = BufReader::new(input_file);
    let mut temp = create_tracked_tempfile(&parent, TEMP_FILE_PREFIX)?;

    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        writer.write_all(&header_bytes)?;
        encrypt_stream(
            &mut reader,
            &mut writer,
            &content_cipher,
            &content_aad,
            &header.content_nonce_prefix,
            header.chunk_size as usize,
            cancel_flag,
        )?;
        writer.flush()?;
    }

    temp.as_file_mut().sync_all()?;

    wrapping_key.zeroize();
    fek.zeroize();
    wrapped_plaintext.zeroize();
    wrapped_key_material.zeroize();

    persist_tempfile_noclobber(temp, output)?;
    Ok(())
}

#[cfg(test)]
fn encrypt_file_v3_for_test(
    input: &Path,
    output: &Path,
    password: &str,
    options: &EncryptOptions,
) -> Result<(), VaultError> {
    ensure_file_input(input)?;
    ensure_output_target(input, output)?;

    let input_size = fs::metadata(input)?.len();
    let mut header = HeaderV3::new(input_size, &options.config, options.keyfile.is_some())?;

    let mut password_wrap_key = derive_password_wrap_key_v3(password, &header)?;
    let password_wrap_cipher =
        Aes256Gcm::new_from_slice(&password_wrap_key).map_err(|_| VaultError::EncryptionFailure)?;

    let mut fek = [0u8; FEK_LEN];
    OsRng.fill_bytes(&mut fek);

    let wrap_aad = header.wrap_aad();
    let mut wrapped_fek = password_wrap_cipher
        .encrypt(
            Nonce::from_slice(&header.password_wrap_nonce),
            Payload {
                msg: &fek,
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::EncryptionFailure)?;

    if header.requires_keyfile() {
        let keyfile = options.keyfile.as_deref().ok_or(VaultError::KeyfileRequired)?;
        let mut keyfile_wrap_key = derive_keyfile_wrap_key_v3(keyfile, &header)?;
        let keyfile_wrap_cipher =
            Aes256Gcm::new_from_slice(&keyfile_wrap_key).map_err(|_| VaultError::EncryptionFailure)?;
        let mut doubly_wrapped_fek = keyfile_wrap_cipher
            .encrypt(
                Nonce::from_slice(&header.keyfile_wrap_nonce),
                Payload {
                    msg: wrapped_fek.as_slice(),
                    aad: &wrap_aad,
                },
            )
            .map_err(|_| VaultError::EncryptionFailure)?;
        wrapped_fek.zeroize();
        header.set_wrapped_fek(&doubly_wrapped_fek)?;
        keyfile_wrap_key.zeroize();
        doubly_wrapped_fek.zeroize();
    } else {
        header.set_wrapped_fek(&wrapped_fek)?;
    }

    let header_bytes = header.encode();

    let content_cipher = Aes256Gcm::new_from_slice(&fek).map_err(|_| VaultError::EncryptionFailure)?;

    let parent = resolve_parent_directory(output)?;
    let input_file = File::open(input)?;
    let mut reader = BufReader::new(input_file);
    let mut temp = create_tracked_tempfile(&parent, TEMP_FILE_PREFIX)?;

    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        writer.write_all(&header_bytes)?;
        encrypt_stream(
            &mut reader,
            &mut writer,
            &content_cipher,
            &header_bytes,
            &header.content_nonce_prefix,
            header.chunk_size as usize,
            None,
        )?;
        writer.flush()?;
    }

    temp.as_file_mut().sync_all()?;

    password_wrap_key.zeroize();
    fek.zeroize();
    wrapped_fek.zeroize();

    persist_tempfile_noclobber(temp, output)?;
    Ok(())
}

pub fn decrypt_file(
    input: &Path,
    output: &Path,
    password: &str,
    options: &DecryptOptions,
) -> Result<(), VaultError> {
    decrypt_file_with_optional_cancel(input, output, password, options, None)
}

pub fn decrypt_file_with_cancel(
    input: &Path,
    output: &Path,
    password: &str,
    options: &DecryptOptions,
    cancel_flag: &AtomicBool,
) -> Result<(), VaultError> {
    decrypt_file_with_optional_cancel(input, output, password, options, Some(cancel_flag))
}

fn decrypt_file_with_optional_cancel(
    input: &Path,
    output: &Path,
    password: &str,
    options: &DecryptOptions,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    ensure_file_input(input)?;
    ensure_output_target(input, output)?;
    check_cancelled(cancel_flag)?;

    let version = read_magic_and_version(input)?;
    match version {
        VERSION_V1 => decrypt_file_v1(input, output, password, cancel_flag),
        VERSION_V2 => decrypt_file_v2(input, output, password, options.keyfile.as_deref(), cancel_flag),
        VERSION_V3 => decrypt_file_v3(input, output, password, options.keyfile.as_deref(), cancel_flag),
        VERSION_V4 => decrypt_file_v4(input, output, password, options.keyfile.as_deref(), cancel_flag),
        other => Err(VaultError::UnsupportedVersion(other)),
    }
}

fn decrypt_file_v4(
    input: &Path,
    output: &Path,
    password: &str,
    keyfile: Option<&Path>,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    match decrypt_file_v4_inner(input, output, password, keyfile, false, cancel_flag) {
        Ok(()) => Ok(()),
        Err(VaultError::AuthenticationFailed) => {
            decrypt_file_v4_inner(input, output, password, keyfile, true, cancel_flag)
        }
        Err(error) => Err(error),
    }
}

fn decrypt_file_v4_inner(
    input: &Path,
    output: &Path,
    password: &str,
    keyfile: Option<&Path>,
    use_legacy_content_aad: bool,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    let input_file = File::open(input)?;
    let mut reader = BufReader::new(input_file);

    let (header, header_bytes) = read_header_v4(&mut reader)?;
    let (plaintext_size, mut fek) = decode_wrapped_key_material_v4(password, keyfile, &header)?;

    let content_cipher = Aes256Gcm::new_from_slice(&fek).map_err(|_| VaultError::EncryptionFailure)?;
    let parent = resolve_parent_directory(output)?;
    let mut temp = create_tracked_tempfile(&parent, TEMP_FILE_PREFIX)?;
    let content_aad = header.content_aad();

    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        let written = decrypt_stream(
            &mut reader,
            &mut writer,
            &content_cipher,
            if use_legacy_content_aad {
                &header_bytes
            } else {
                &content_aad
            },
            header.chunk_size as usize,
            &header.content_nonce_prefix,
            cancel_flag,
        )?;
        if written != plaintext_size {
            return Err(VaultError::InvalidFormat);
        }
        writer.flush()?;
    }

    temp.as_file_mut().sync_all()?;
    fek.zeroize();

    persist_tempfile_noclobber(temp, output)?;
    Ok(())
}

fn decrypt_file_v2(
    input: &Path,
    output: &Path,
    password: &str,
    keyfile: Option<&Path>,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    let input_file = File::open(input)?;
    let mut reader = BufReader::new(input_file);

    let (header, header_bytes) = read_header_v2(&mut reader)?;
    let mut wrapping_key = derive_wrapping_key_v2(password, keyfile, &header)?;
    let wrapping_cipher =
        Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| VaultError::EncryptionFailure)?;

    let wrap_aad = header.wrap_aad();
    let mut fek_vec = wrapping_cipher
        .decrypt(
            Nonce::from_slice(&header.wrapped_fek_nonce),
            Payload {
                msg: &header.wrapped_fek,
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;

    if fek_vec.len() != FEK_LEN {
        fek_vec.zeroize();
        return Err(VaultError::InvalidFormat);
    }

    let mut fek = [0u8; FEK_LEN];
    fek.copy_from_slice(&fek_vec);
    fek_vec.zeroize();
    wrapping_key.zeroize();

    let content_cipher = Aes256Gcm::new_from_slice(&fek).map_err(|_| VaultError::EncryptionFailure)?;
    let parent = resolve_parent_directory(output)?;
    let mut temp = create_tracked_tempfile(&parent, TEMP_FILE_PREFIX)?;

    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        let written = decrypt_stream(
            &mut reader,
            &mut writer,
            &content_cipher,
            &header_bytes,
            header.chunk_size as usize,
            &header.content_nonce_prefix,
            cancel_flag,
        )?;
        if written != header.plaintext_size {
            return Err(VaultError::InvalidFormat);
        }
        writer.flush()?;
    }

    temp.as_file_mut().sync_all()?;
    fek.zeroize();

    persist_tempfile_noclobber(temp, output)?;
    Ok(())
}

fn decrypt_file_v3(
    input: &Path,
    output: &Path,
    password: &str,
    keyfile: Option<&Path>,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    let input_file = File::open(input)?;
    let mut reader = BufReader::new(input_file);

    let (header, header_bytes) = read_header_v3(&mut reader)?;
    let wrap_aad = header.wrap_aad();

    let mut wrapped_fek = header.wrapped_fek_bytes().to_vec();
    if header.requires_keyfile() {
        let path = keyfile.ok_or(VaultError::KeyfileRequired)?;
        let mut keyfile_wrap_key = derive_keyfile_wrap_key_v3(path, &header)?;
        let keyfile_wrap_cipher =
            Aes256Gcm::new_from_slice(&keyfile_wrap_key).map_err(|_| VaultError::EncryptionFailure)?;
        let mut inner_wrapped_fek = keyfile_wrap_cipher
            .decrypt(
                Nonce::from_slice(&header.keyfile_wrap_nonce),
                Payload {
                    msg: wrapped_fek.as_slice(),
                    aad: &wrap_aad,
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;
        wrapped_fek.zeroize();
        keyfile_wrap_key.zeroize();

        if inner_wrapped_fek.len() != WRAPPED_FEK_LEN {
            inner_wrapped_fek.zeroize();
            return Err(VaultError::InvalidFormat);
        }
        wrapped_fek = inner_wrapped_fek;
    }

    let mut password_wrap_key = derive_password_wrap_key_v3(password, &header)?;
    let password_wrap_cipher =
        Aes256Gcm::new_from_slice(&password_wrap_key).map_err(|_| VaultError::EncryptionFailure)?;
    let mut fek_vec = password_wrap_cipher
        .decrypt(
            Nonce::from_slice(&header.password_wrap_nonce),
            Payload {
                msg: wrapped_fek.as_slice(),
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    wrapped_fek.zeroize();
    password_wrap_key.zeroize();

    if fek_vec.len() != FEK_LEN {
        fek_vec.zeroize();
        return Err(VaultError::InvalidFormat);
    }

    let mut fek = [0u8; FEK_LEN];
    fek.copy_from_slice(&fek_vec);
    fek_vec.zeroize();

    let content_cipher = Aes256Gcm::new_from_slice(&fek).map_err(|_| VaultError::EncryptionFailure)?;
    let parent = resolve_parent_directory(output)?;
    let mut temp = create_tracked_tempfile(&parent, TEMP_FILE_PREFIX)?;

    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        let written = decrypt_stream(
            &mut reader,
            &mut writer,
            &content_cipher,
            &header_bytes,
            header.chunk_size as usize,
            &header.content_nonce_prefix,
            cancel_flag,
        )?;
        if written != header.plaintext_size {
            return Err(VaultError::InvalidFormat);
        }
        writer.flush()?;
    }

    temp.as_file_mut().sync_all()?;
    fek.zeroize();

    persist_tempfile_noclobber(temp, output)?;
    Ok(())
}

fn decrypt_file_v1(
    input: &Path,
    output: &Path,
    password: &str,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    let input_file = File::open(input)?;
    let mut reader = BufReader::new(input_file);

    let (header, header_bytes) = read_header_v1(&mut reader)?;
    let mut key = derive_key_v1(password, &header)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| VaultError::EncryptionFailure)?;

    let parent = resolve_parent_directory(output)?;
    let mut temp = create_tracked_tempfile(&parent, TEMP_FILE_PREFIX)?;

    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        let _ = decrypt_stream(
            &mut reader,
            &mut writer,
            &cipher,
            &header_bytes,
            header.chunk_size as usize,
            &header.nonce_prefix,
            cancel_flag,
        )?;
        writer.flush()?;
    }

    temp.as_file_mut().sync_all()?;
    key.zeroize();

    persist_tempfile_noclobber(temp, output)?;
    Ok(())
}

fn read_magic_and_version(path: &Path) -> Result<u8, VaultError> {
    let mut file = File::open(path)?;
    let mut prefix = [0u8; 5];
    read_exact_or_format(&mut file, &mut prefix)?;
    if &prefix[0..4] != &MAGIC {
        return Err(VaultError::InvalidFormat);
    }
    Ok(prefix[4])
}

fn ensure_file_input(path: &Path) -> Result<(), VaultError> {
    let meta = fs::metadata(path).map_err(|_| VaultError::InvalidInputPath)?;
    if !meta.is_file() {
        return Err(VaultError::InvalidInputPath);
    }
    Ok(())
}

fn resolve_parent_directory(path: &Path) -> Result<PathBuf, VaultError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };

    let meta = fs::metadata(&parent).map_err(|_| VaultError::NoParentDirectory)?;
    if !meta.is_dir() {
        return Err(VaultError::NoParentDirectory);
    }

    Ok(parent)
}

fn ensure_output_target(input: &Path, output: &Path) -> Result<(), VaultError> {
    if input == output {
        return Err(VaultError::SameInputAndOutput);
    }
    if output.exists() {
        return Err(VaultError::OutputExists(output.display().to_string()));
    }
    Ok(())
}

fn persist_tempfile_noclobber(temp: NamedTempFile, output: &Path) -> Result<(), VaultError> {
    let temp_path = temp.path().to_path_buf();
    temp.persist_noclobber(output)
        .map(|_| ())
        .inspect(|_| {
            let _ = unregister_temp_path(&temp_path);
        })
        .map_err(|error| {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                VaultError::OutputExists(output.display().to_string())
            } else {
                VaultError::Io(error.error)
            }
        })
}

fn validate_config(config: &VaultConfig) -> Result<(), VaultError> {
    if config.chunk_size == 0 || config.chunk_size > MAX_CHUNK_SIZE {
        return Err(VaultError::InvalidConfiguration("chunk_size must be 1..=8 MiB"));
    }
    if !(MIN_ARGON_MEMORY_KIB..=MAX_ARGON_MEMORY_KIB).contains(&config.argon_memory_kib) {
        return Err(VaultError::InvalidConfiguration(
            "argon_memory_kib must be between 65536 and 524288",
        ));
    }
    if !(1..=MAX_ARGON_ITERATIONS).contains(&config.argon_iterations) {
        return Err(VaultError::InvalidConfiguration(
            "argon_iterations must be between 1 and 10",
        ));
    }
    if !(1..=MAX_ARGON_LANES).contains(&config.argon_lanes) {
        return Err(VaultError::InvalidConfiguration(
            "argon_lanes must be between 1 and 8",
        ));
    }
    Ok(())
}

fn create_tracked_tempfile(parent: &Path, prefix: &str) -> Result<NamedTempFile, VaultError> {
    let temp = Builder::new()
        .prefix(prefix)
        .suffix(TEMP_FILE_SUFFIX)
        .tempfile_in(parent)?;
    mark_tempfile_hidden(temp.path())?;
    register_temp_path(temp.path())?;
    Ok(temp)
}

#[cfg(not(test))]
fn temp_tracking_path() -> PathBuf {
    std::env::temp_dir().join(TEMP_TRACKING_FILE_NAME)
}

#[cfg(test)]
fn temp_tracking_path() -> PathBuf {
    let thread_tag = format!("{:?}", std::thread::current().id());
    std::env::temp_dir().join(format!("{thread_tag}-{TEMP_TRACKING_FILE_NAME}"))
}

fn register_temp_path(path: &Path) -> io::Result<()> {
    let tracking_path = temp_tracking_path();
    let mut entries = tracked_temp_paths()?;
    let owned = path.to_path_buf();
    if !entries.iter().any(|candidate| candidate == &owned) {
        entries.push(owned);
        write_tracked_temp_paths(&tracking_path, &entries)?;
    }
    Ok(())
}

fn unregister_temp_path(path: &Path) -> io::Result<()> {
    let tracking_path = temp_tracking_path();
    let entries = tracked_temp_paths()?;
    let filtered: Vec<PathBuf> = entries.into_iter().filter(|candidate| candidate != path).collect();
    write_tracked_temp_paths(&tracking_path, &filtered)
}

fn tracked_temp_paths() -> io::Result<Vec<PathBuf>> {
    let tracking_path = temp_tracking_path();
    let content = match fs::read_to_string(&tracking_path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };

    Ok(content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(PathBuf::from)
        .collect())
}

fn write_tracked_temp_paths(tracking_path: &Path, entries: &[PathBuf]) -> io::Result<()> {
    if entries.is_empty() {
        match fs::remove_file(tracking_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }?;
        return Ok(());
    }

    let mut content = String::new();
    for entry in entries {
        content.push_str(&entry.to_string_lossy());
        content.push('\n');
    }
    fs::write(tracking_path, content)
}

fn is_pillowlock_temp_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    name.ends_with(TEMP_FILE_SUFFIX)
        && (name.starts_with(TEMP_FILE_PREFIX) || name.starts_with(TEMP_KEYFILE_PREFIX))
}

pub fn cleanup_stale_tempfiles() -> io::Result<usize> {
    let tracking_path = temp_tracking_path();
    let mut survivors = Vec::new();
    let mut removed = 0usize;

    for path in tracked_temp_paths()? {
        if !is_pillowlock_temp_path(&path) {
            continue;
        }

        match fs::remove_file(&path) {
            Ok(()) => {
                removed += 1;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                survivors.push(path);
            }
        }
    }

    write_tracked_temp_paths(&tracking_path, &survivors)?;
    Ok(removed)
}

#[cfg(windows)]
fn mark_tempfile_hidden(path: &Path) -> io::Result<()> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let result = unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn mark_tempfile_hidden(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn derive_wrapping_key_v2(
    password: &str,
    keyfile: Option<&Path>,
    header: &HeaderV2,
) -> Result<[u8; 32], VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }

    let mut keyfile_digest = [0u8; KEYFILE_DIGEST_LEN];
    if header.requires_keyfile() {
        let path = keyfile.ok_or(VaultError::KeyfileRequired)?;
        keyfile_digest = hash_keyfile(path)?;
    }

    let params = Params::new(
        header.argon_memory_kib,
        header.argon_iterations,
        header.argon_lanes,
        Some(32),
    )
    .map_err(|_| VaultError::InvalidFormat)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &header.kdf_salt, &mut master)?;

    let hk = Hkdf::<Sha512>::new(Some(&keyfile_digest), &master);
    let mut wrapping_key = [0u8; 32];
    hk.expand(
        b"RVLT-v2/AES-256-GCM/FEK-WRAP",
        &mut wrapping_key,
    )
    .map_err(|_| VaultError::KeyExpansion)?;

    master.zeroize();
    keyfile_digest.zeroize();

    Ok(wrapping_key)
}

fn derive_password_wrap_key_v3(password: &str, header: &HeaderV3) -> Result<[u8; 32], VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }

    let params = Params::new(
        header.argon_memory_kib,
        header.argon_iterations,
        header.argon_lanes,
        Some(32),
    )
    .map_err(|_| VaultError::InvalidFormat)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut master = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &header.password_kdf_salt, &mut master)?;

    let hk = Hkdf::<Sha512>::new(None, &master);
    let mut wrapping_key = [0u8; 32];
    hk.expand(
        b"RVLT-v3/AES-256-GCM/PASSWORD-WRAP",
        &mut wrapping_key,
    )
    .map_err(|_| VaultError::KeyExpansion)?;
    master.zeroize();

    Ok(wrapping_key)
}

fn derive_keyfile_wrap_key_v3(keyfile: &Path, header: &HeaderV3) -> Result<[u8; 32], VaultError> {
    let mut keyfile_digest = hash_keyfile(keyfile)?;
    let hk = Hkdf::<Sha512>::new(Some(&header.keyfile_kdf_salt), &keyfile_digest);
    let mut wrapping_key = [0u8; 32];
    hk.expand(
        b"RVLT-v3/AES-256-GCM/KEYFILE-WRAP",
        &mut wrapping_key,
    )
    .map_err(|_| VaultError::KeyExpansion)?;
    keyfile_digest.zeroize();

    Ok(wrapping_key)
}

fn derive_wrapping_key_v4(
    password: &str,
    keyfile: Option<&Path>,
    header: &HeaderV4,
) -> Result<[u8; 32], VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }

    let params = Params::new(
        header.argon_memory_kib,
        header.argon_iterations,
        header.argon_lanes,
        Some(32),
    )
    .map_err(|_| VaultError::InvalidFormat)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut password_master = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &header.password_kdf_salt, &mut password_master)?;

    let mut combined_input = [0u8; 32 + KEYFILE_DIGEST_LEN];
    combined_input[..32].copy_from_slice(&password_master);
    let combined_len = if header.requires_keyfile() {
        let path = keyfile.ok_or(VaultError::KeyfileRequired)?;
        let mut keyfile_digest = hash_keyfile(path)?;
        combined_input[32..].copy_from_slice(&keyfile_digest);
        keyfile_digest.zeroize();
        combined_input.len()
    } else {
        32
    };

    let binding_salt = header.key_binding_salt_bytes();
    let hk = Hkdf::<Sha512>::new(Some(&binding_salt), &combined_input[..combined_len]);
    let mut wrapping_key = [0u8; 32];
    hk.expand(
        b"RVLT-v4/AES-256-GCM/BOUND-WRAP",
        &mut wrapping_key,
    )
    .map_err(|_| VaultError::KeyExpansion)?;

    password_master.zeroize();
    combined_input.zeroize();

    Ok(wrapping_key)
}

fn decode_wrapped_key_material_v4(
    password: &str,
    keyfile: Option<&Path>,
    header: &HeaderV4,
) -> Result<(u64, [u8; FEK_LEN]), VaultError> {
    let mut wrapping_key = derive_wrapping_key_v4(password, keyfile, header)?;
    let wrapping_cipher =
        Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| VaultError::EncryptionFailure)?;

    let wrap_aad = header.wrap_aad();
    let mut wrapped_key_material = header.wrapped_key_material.to_vec();
    let mut key_material = wrapping_cipher
        .decrypt(
            Nonce::from_slice(&header.wrapping_nonce),
            Payload {
                msg: wrapped_key_material.as_slice(),
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    wrapped_key_material.zeroize();
    wrapping_key.zeroize();

    if key_material.len() != WRAPPED_KEY_MATERIAL_V4_PLAINTEXT_LEN {
        key_material.zeroize();
        return Err(VaultError::InvalidFormat);
    }

    let plaintext_size = u64::from_le_bytes(
        key_material[..8]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?,
    );
    let mut fek = [0u8; FEK_LEN];
    fek.copy_from_slice(&key_material[8..8 + FEK_LEN]);
    key_material.zeroize();

    Ok((plaintext_size, fek))
}

fn verify_vault_v1(path: &Path, password: &str) -> Result<(), VaultError> {
    let input_file = File::open(path)?;
    let mut reader = BufReader::new(input_file);
    let (header, header_bytes) = read_header_v1(&mut reader)?;
    let mut key = derive_key_v1(password, &header)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| VaultError::EncryptionFailure)?;
    let mut sink = io::sink();
    let _ = decrypt_stream(
        &mut reader,
        &mut sink,
        &cipher,
        &header_bytes,
        header.chunk_size as usize,
        &header.nonce_prefix,
        None,
    )?;
    key.zeroize();
    Ok(())
}

fn verify_vault_v2(path: &Path, password: &str, keyfile: Option<&Path>) -> Result<(), VaultError> {
    let input_file = File::open(path)?;
    let mut reader = BufReader::new(input_file);
    let (header, header_bytes) = read_header_v2(&mut reader)?;
    let mut wrapping_key = derive_wrapping_key_v2(password, keyfile, &header)?;
    let wrapping_cipher =
        Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| VaultError::EncryptionFailure)?;

    let wrap_aad = header.wrap_aad();
    let mut fek_vec = wrapping_cipher
        .decrypt(
            Nonce::from_slice(&header.wrapped_fek_nonce),
            Payload {
                msg: &header.wrapped_fek,
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    wrapping_key.zeroize();
    if fek_vec.len() != FEK_LEN {
        fek_vec.zeroize();
        return Err(VaultError::InvalidFormat);
    }

    let mut fek = [0u8; FEK_LEN];
    fek.copy_from_slice(&fek_vec);
    fek_vec.zeroize();

    let content_cipher = Aes256Gcm::new_from_slice(&fek).map_err(|_| VaultError::EncryptionFailure)?;
    let mut sink = io::sink();
    let written = decrypt_stream(
        &mut reader,
        &mut sink,
        &content_cipher,
        &header_bytes,
        header.chunk_size as usize,
        &header.content_nonce_prefix,
        None,
    )?;
    fek.zeroize();
    if written != header.plaintext_size {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn verify_vault_v3(path: &Path, password: &str, keyfile: Option<&Path>) -> Result<(), VaultError> {
    let input_file = File::open(path)?;
    let mut reader = BufReader::new(input_file);
    let (header, header_bytes) = read_header_v3(&mut reader)?;
    let wrap_aad = header.wrap_aad();

    let mut wrapped_fek = header.wrapped_fek_bytes().to_vec();
    if header.requires_keyfile() {
        let path = keyfile.ok_or(VaultError::KeyfileRequired)?;
        let mut keyfile_wrap_key = derive_keyfile_wrap_key_v3(path, &header)?;
        let keyfile_wrap_cipher =
            Aes256Gcm::new_from_slice(&keyfile_wrap_key).map_err(|_| VaultError::EncryptionFailure)?;
        let mut inner_wrapped_fek = keyfile_wrap_cipher
            .decrypt(
                Nonce::from_slice(&header.keyfile_wrap_nonce),
                Payload {
                    msg: wrapped_fek.as_slice(),
                    aad: &wrap_aad,
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;
        wrapped_fek.zeroize();
        keyfile_wrap_key.zeroize();

        if inner_wrapped_fek.len() != WRAPPED_FEK_LEN {
            inner_wrapped_fek.zeroize();
            return Err(VaultError::InvalidFormat);
        }
        wrapped_fek = inner_wrapped_fek;
    }

    let mut password_wrap_key = derive_password_wrap_key_v3(password, &header)?;
    let password_wrap_cipher =
        Aes256Gcm::new_from_slice(&password_wrap_key).map_err(|_| VaultError::EncryptionFailure)?;
    let mut fek_vec = password_wrap_cipher
        .decrypt(
            Nonce::from_slice(&header.password_wrap_nonce),
            Payload {
                msg: wrapped_fek.as_slice(),
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    wrapped_fek.zeroize();
    password_wrap_key.zeroize();

    if fek_vec.len() != FEK_LEN {
        fek_vec.zeroize();
        return Err(VaultError::InvalidFormat);
    }

    let mut fek = [0u8; FEK_LEN];
    fek.copy_from_slice(&fek_vec);
    fek_vec.zeroize();

    let content_cipher = Aes256Gcm::new_from_slice(&fek).map_err(|_| VaultError::EncryptionFailure)?;
    let mut sink = io::sink();
    let written = decrypt_stream(
        &mut reader,
        &mut sink,
        &content_cipher,
        &header_bytes,
        header.chunk_size as usize,
        &header.content_nonce_prefix,
        None,
    )?;
    fek.zeroize();
    if written != header.plaintext_size {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn verify_vault_v4(path: &Path, password: &str, keyfile: Option<&Path>) -> Result<(), VaultError> {
    let input_file = File::open(path)?;
    let mut reader = BufReader::new(input_file);
    let (header, _) = read_header_v4(&mut reader)?;
    let (plaintext_size, mut fek) = decode_wrapped_key_material_v4(password, keyfile, &header)?;

    let result = match verify_vault_v4_with_aad(path, &header, plaintext_size, &fek, false) {
        Ok(()) => Ok(()),
        Err(VaultError::AuthenticationFailed) => {
            verify_vault_v4_with_aad(path, &header, plaintext_size, &fek, true)
        }
        Err(error) => Err(error),
    };
    fek.zeroize();
    result
}

fn verify_vault_v4_with_aad(
    path: &Path,
    header: &HeaderV4,
    plaintext_size: u64,
    fek: &[u8; FEK_LEN],
    use_legacy_content_aad: bool,
) -> Result<(), VaultError> {
    let input_file = File::open(path)?;
    let mut reader = BufReader::new(input_file);
    let (_, header_bytes) = read_header_v4(&mut reader)?;
    let content_aad = header.content_aad();
    let content_cipher = Aes256Gcm::new_from_slice(fek).map_err(|_| VaultError::EncryptionFailure)?;
    let mut sink = io::sink();
    let written = decrypt_stream(
        &mut reader,
        &mut sink,
        &content_cipher,
        if use_legacy_content_aad {
            &header_bytes
        } else {
            &content_aad
        },
        header.chunk_size as usize,
        &header.content_nonce_prefix,
        None,
    )?;
    if written != plaintext_size {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn hash_keyfile(path: &Path) -> Result<[u8; KEYFILE_DIGEST_LEN], VaultError> {
    let meta = fs::metadata(path).map_err(|_| VaultError::InvalidKeyfilePath)?;
    if !meta.is_file() {
        return Err(VaultError::InvalidKeyfilePath);
    }
    if meta.len() > MAX_KEYFILE_SIZE_BYTES {
        return Err(VaultError::KeyfileTooLarge(meta.len()));
    }

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha512::new();
    let mut buf = [0u8; 8192];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let digest = hasher.finalize();
    let mut out = [0u8; KEYFILE_DIGEST_LEN];
    out.copy_from_slice(&digest[..]);
    buf.zeroize();

    Ok(out)
}

fn derive_key_v1(password: &str, header: &HeaderV1) -> Result<[u8; 32], VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }

    let params = Params::new(
        header.argon_memory_kib,
        header.argon_iterations,
        header.argon_lanes,
        Some(32),
    )
    .map_err(|_| VaultError::InvalidFormat)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), &header.salt, &mut key)?;
    Ok(key)
}

fn read_header_v3<R: Read>(reader: &mut R) -> Result<(HeaderV3, [u8; HEADER_V3_LEN]), VaultError> {
    let mut bytes = [0u8; HEADER_V3_LEN];
    read_exact_or_format(reader, &mut bytes)?;
    let header = HeaderV3::decode(&bytes)?;
    Ok((header, bytes))
}

fn read_header_v4<R: Read>(reader: &mut R) -> Result<(HeaderV4, [u8; HEADER_V4_LEN]), VaultError> {
    let mut bytes = [0u8; HEADER_V4_LEN];
    read_exact_or_format(reader, &mut bytes)?;
    let header = HeaderV4::decode(&bytes)?;
    Ok((header, bytes))
}

fn read_header_v2<R: Read>(reader: &mut R) -> Result<(HeaderV2, [u8; HEADER_V2_LEN]), VaultError> {
    let mut bytes = [0u8; HEADER_V2_LEN];
    read_exact_or_format(reader, &mut bytes)?;
    let header = HeaderV2::decode(&bytes)?;
    Ok((header, bytes))
}

fn read_header_v1<R: Read>(reader: &mut R) -> Result<(HeaderV1, [u8; LEGACY_HEADER_LEN]), VaultError> {
    let mut bytes = [0u8; LEGACY_HEADER_LEN];
    read_exact_or_format(reader, &mut bytes)?;
    let header = HeaderV1::decode(&bytes)?;
    Ok((header, bytes))
}

pub fn inspect_vault(path: &Path) -> Result<VaultSummary, VaultError> {
    ensure_file_input(path)?;

    match read_magic_and_version(path)? {
        VERSION_V1 => {
            let input_file = File::open(path)?;
            let mut reader = BufReader::new(input_file);
            let (header, _) = read_header_v1(&mut reader)?;
            Ok(VaultSummary {
                version: VERSION_V1,
                cipher: "AES-256-GCM",
                kdf: "Argon2id",
                key_wrap: "Direct content key",
                keyfile_required: false,
                chunk_size: header.chunk_size,
                argon_memory_kib: header.argon_memory_kib,
                argon_iterations: header.argon_iterations,
                argon_lanes: header.argon_lanes,
                supports_rewrap: false,
            })
        }
        VERSION_V2 => {
            let input_file = File::open(path)?;
            let mut reader = BufReader::new(input_file);
            let (header, _) = read_header_v2(&mut reader)?;
            Ok(VaultSummary {
                version: VERSION_V2,
                cipher: "AES-256-GCM",
                kdf: "Argon2id",
                key_wrap: "HKDF-wrapped FEK",
                keyfile_required: header.requires_keyfile(),
                chunk_size: header.chunk_size,
                argon_memory_kib: header.argon_memory_kib,
                argon_iterations: header.argon_iterations,
                argon_lanes: header.argon_lanes,
                supports_rewrap: false,
            })
        }
        VERSION_V3 => {
            let input_file = File::open(path)?;
            let mut reader = BufReader::new(input_file);
            let (header, _) = read_header_v3(&mut reader)?;
            Ok(VaultSummary {
                version: VERSION_V3,
                cipher: "AES-256-GCM",
                kdf: "Argon2id",
                key_wrap: "Layered password/keyfile wrap",
                keyfile_required: header.requires_keyfile(),
                chunk_size: header.chunk_size,
                argon_memory_kib: header.argon_memory_kib,
                argon_iterations: header.argon_iterations,
                argon_lanes: header.argon_lanes,
                supports_rewrap: false,
            })
        }
        VERSION_V4 => {
            let input_file = File::open(path)?;
            let mut reader = BufReader::new(input_file);
            let (header, _) = read_header_v4(&mut reader)?;
            Ok(VaultSummary {
                version: VERSION_V4,
                cipher: "AES-256-GCM",
                kdf: "Argon2id",
                key_wrap: "Bound password+keyfile wrap",
                keyfile_required: header.requires_keyfile(),
                chunk_size: header.chunk_size,
                argon_memory_kib: header.argon_memory_kib,
                argon_iterations: header.argon_iterations,
                argon_lanes: header.argon_lanes,
                supports_rewrap: true,
            })
        }
        other => Err(VaultError::UnsupportedVersion(other)),
    }
}

pub fn verify_vault(
    path: &Path,
    password: &str,
    keyfile: Option<&Path>,
) -> Result<(), VaultError> {
    ensure_file_input(path)?;

    match read_magic_and_version(path)? {
        VERSION_V1 => verify_vault_v1(path, password),
        VERSION_V2 => verify_vault_v2(path, password, keyfile),
        VERSION_V3 => verify_vault_v3(path, password, keyfile),
        VERSION_V4 => verify_vault_v4(path, password, keyfile),
        other => Err(VaultError::UnsupportedVersion(other)),
    }
}

pub fn rewrap_vault(
    input: &Path,
    output: &Path,
    old_password: &str,
    old_keyfile: Option<&Path>,
    new_password: &str,
    new_keyfile: Option<&Path>,
) -> Result<(), VaultError> {
    ensure_file_input(input)?;
    ensure_output_target(input, output)?;

    let version = read_magic_and_version(input)?;
    if version != VERSION_V4 {
        return Err(VaultError::UnsupportedRewrapVersion(version));
    }

    let input_file = File::open(input)?;
    let mut reader = BufReader::new(input_file);
    let (old_header, _) = read_header_v4(&mut reader)?;
    let (plaintext_size, mut fek) = decode_wrapped_key_material_v4(old_password, old_keyfile, &old_header)?;

    if verify_vault_v4_with_aad(input, &old_header, plaintext_size, &fek, false).is_err() {
        fek.zeroize();
        return Err(VaultError::UnsupportedRewrapLayout);
    }

    let mut new_header = old_header.clone();
    new_header.flags = if new_keyfile.is_some() {
        HEADER_FLAG_KEYFILE_REQUIRED
    } else {
        0
    };
    OsRng.fill_bytes(&mut new_header.password_kdf_salt);
    OsRng.fill_bytes(&mut new_header.wrapping_nonce);
    OsRng.fill_bytes(&mut new_header.key_binding_salt);
    OsRng.fill_bytes(&mut new_header.key_binding_nonce);

    let mut wrapping_key = derive_wrapping_key_v4(new_password, new_keyfile, &new_header)?;
    let wrapping_cipher =
        Aes256Gcm::new_from_slice(&wrapping_key).map_err(|_| VaultError::EncryptionFailure)?;

    let mut wrapped_plaintext = [0u8; WRAPPED_KEY_MATERIAL_V4_PLAINTEXT_LEN];
    wrapped_plaintext[..8].copy_from_slice(&plaintext_size.to_le_bytes());
    wrapped_plaintext[8..].copy_from_slice(&fek);

    let wrap_aad = new_header.wrap_aad();
    let wrapped_key_material = wrapping_cipher
        .encrypt(
            Nonce::from_slice(&new_header.wrapping_nonce),
            Payload {
                msg: &wrapped_plaintext,
                aad: &wrap_aad,
            },
        )
        .map_err(|_| VaultError::EncryptionFailure)?;
    new_header.set_wrapped_key_material(&wrapped_key_material)?;

    let new_header_bytes = new_header.encode();
    let parent = resolve_parent_directory(output)?;
    let mut temp = create_tracked_tempfile(&parent, TEMP_FILE_PREFIX)?;
    {
        let mut writer = BufWriter::new(temp.as_file_mut());
        writer.write_all(&new_header_bytes)?;

        let input_file = File::open(input)?;
        let mut reader = BufReader::new(input_file);
        let mut discard = [0u8; HEADER_V4_LEN];
        read_exact_or_format(&mut reader, &mut discard)?;
        io::copy(&mut reader, &mut writer)?;
        writer.flush()?;
    }

    temp.as_file_mut().sync_all()?;
    wrapping_key.zeroize();
    fek.zeroize();
    wrapped_plaintext.zeroize();

    persist_tempfile_noclobber(temp, output)
}

fn read_exact_or_format<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), VaultError> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            VaultError::InvalidFormat
        } else {
            VaultError::Io(e)
        }
    })
}

fn check_cancelled(cancel_flag: Option<&AtomicBool>) -> Result<(), VaultError> {
    if cancel_flag
        .map(|flag| flag.load(Ordering::Relaxed))
        .unwrap_or(false)
    {
        Err(VaultError::Cancelled)
    } else {
        Ok(())
    }
}

fn fill_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, VaultError> {
    let mut total = 0usize;
    while total < buf.len() {
        let n = reader.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cipher: &Aes256Gcm,
    aad_header_bytes: &[u8],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    chunk_size: usize,
    cancel_flag: Option<&AtomicBool>,
) -> Result<(), VaultError> {
    check_cancelled(cancel_flag)?;
    let mut current = vec![0u8; chunk_size];
    let current_len = fill_chunk(reader, &mut current)?;

    if current_len == 0 {
        write_encrypted_chunk(
            writer,
            cipher,
            aad_header_bytes,
            nonce_prefix,
            0,
            FLAG_FINAL,
            &[],
        )?;
        current.zeroize();
        return Ok(());
    }

    current.truncate(current_len);
    let mut index = 0u32;

    loop {
        check_cancelled(cancel_flag)?;
        let mut next = vec![0u8; chunk_size];
        let next_len = fill_chunk(reader, &mut next)?;
        let is_final = next_len == 0;
        let flags = if is_final { FLAG_FINAL } else { 0 };

        write_encrypted_chunk(
            writer,
            cipher,
            aad_header_bytes,
            nonce_prefix,
            index,
            flags,
            &current,
        )?;

        current.zeroize();

        if is_final {
            next.zeroize();
            return Ok(());
        }

        index = index.checked_add(1).ok_or(VaultError::TooManyChunks)?;
        next.truncate(next_len);
        current = next;
    }
}

fn write_encrypted_chunk<W: Write>(
    writer: &mut W,
    cipher: &Aes256Gcm,
    header_bytes: &[u8],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    index: u32,
    flags: u8,
    plaintext: &[u8],
) -> Result<(), VaultError> {
    let nonce_bytes = make_nonce(nonce_prefix, index);
    let aad = make_chunk_aad(header_bytes, index, flags);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| VaultError::EncryptionFailure)?;

    let ct_len = u32::try_from(ciphertext.len()).map_err(|_| VaultError::FileTooLarge)?;
    writer.write_all(&ct_len.to_le_bytes())?;
    writer.write_all(&[flags])?;
    writer.write_all(&ciphertext)?;
    Ok(())
}

fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    cipher: &Aes256Gcm,
    aad_header_bytes: &[u8],
    chunk_size: usize,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    cancel_flag: Option<&AtomicBool>,
) -> Result<u64, VaultError> {
    let mut index = 0u32;
    let mut total_written = 0u64;

    loop {
        check_cancelled(cancel_flag)?;
        let mut len_buf = [0u8; 4];
        read_exact_or_format(reader, &mut len_buf)?;
        let ciphertext_len = u32::from_le_bytes(len_buf) as usize;

        let mut flag_buf = [0u8; 1];
        read_exact_or_format(reader, &mut flag_buf)?;
        let flags = flag_buf[0];
        let is_final = (flags & FLAG_FINAL) != 0;

        if flags & !FLAG_FINAL != 0 {
            return Err(VaultError::InvalidFormat);
        }
        if ciphertext_len < TAG_LEN || ciphertext_len > chunk_size + TAG_LEN {
            return Err(VaultError::InvalidFormat);
        }
        if !is_final && ciphertext_len != chunk_size + TAG_LEN {
            return Err(VaultError::InvalidFormat);
        }

        let mut ciphertext = vec![0u8; ciphertext_len];
        read_exact_or_format(reader, &mut ciphertext)?;

        let nonce_bytes = make_nonce(nonce_prefix, index);
        let aad = make_chunk_aad(aad_header_bytes, index, flags);
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| VaultError::AuthenticationFailed)?;

        writer.write_all(&plaintext)?;

        total_written = total_written
            .checked_add(u64::try_from(plaintext.len()).map_err(|_| VaultError::FileTooLarge)?)
            .ok_or(VaultError::FileTooLarge)?;

        plaintext.zeroize();
        ciphertext.zeroize();

        if is_final {
            let mut trailing = [0u8; 1];
            if reader.read(&mut trailing)? != 0 {
                return Err(VaultError::InvalidFormat);
            }
            return Ok(total_written);
        }

        index = index.checked_add(1).ok_or(VaultError::TooManyChunks)?;
    }
}

fn make_nonce(prefix: &[u8; NONCE_PREFIX_LEN], index: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn make_chunk_aad(header_bytes: &[u8], index: u32, flags: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header_bytes.len() + 5);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.push(flags);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn round_trip_current_format_password_only() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("plain.bin.plock");
        let decrypted = dir.path().join("plain.bin.out");
        let data = b"hello rust vault".repeat(4096);

        fs::write(&input, &data).unwrap();
        encrypt_file(
            &input,
            &encrypted,
            "correct horse battery staple",
            &EncryptOptions::default(),
        )
        .unwrap();
        decrypt_file(
            &encrypted,
            &decrypted,
            "correct horse battery staple",
            &DecryptOptions::default(),
        )
        .unwrap();

        assert_eq!(fs::read(&decrypted).unwrap(), data);
        assert_eq!(read_magic_and_version(&encrypted).unwrap(), VERSION_V4);
    }

    #[test]
    fn round_trip_current_format_with_keyfile() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("plain.bin.plock");
        let decrypted = dir.path().join("plain.bin.out");
        let keyfile = dir.path().join("vault.key");
        let data = b"secret".repeat(2048);

        fs::write(&input, &data).unwrap();
        generate_keyfile(&keyfile).unwrap();

        let enc = EncryptOptions {
            config: VaultConfig::default(),
            keyfile: Some(keyfile.clone()),
        };
        let dec = DecryptOptions {
            keyfile: Some(keyfile.clone()),
        };

        encrypt_file(&input, &encrypted, "right-password", &enc).unwrap();
        decrypt_file(&encrypted, &decrypted, "right-password", &dec).unwrap();

        assert_eq!(fs::read(&decrypted).unwrap(), data);
        assert_eq!(read_magic_and_version(&encrypted).unwrap(), VERSION_V4);
    }

    #[test]
    fn missing_required_keyfile_is_reported() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("plain.bin.plock");
        let keyfile = dir.path().join("vault.key");

        fs::write(&input, b"secret").unwrap();
        generate_keyfile(&keyfile).unwrap();

        let enc = EncryptOptions {
            config: VaultConfig::default(),
            keyfile: Some(keyfile.clone()),
        };

        encrypt_file(&input, &encrypted, "right-password", &enc).unwrap();
        let err = decrypt_file(
            &encrypted,
            &dir.path().join("plain.out"),
            "right-password",
            &DecryptOptions::default(),
        )
        .unwrap_err();

        assert!(matches!(err, VaultError::KeyfileRequired));
    }

    #[test]
    fn wrong_keyfile_is_rejected() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("plain.bin.plock");
        let keyfile = dir.path().join("vault.key");
        let wrong_keyfile = dir.path().join("wrong.key");

        fs::write(&input, b"secret".repeat(512)).unwrap();
        generate_keyfile(&keyfile).unwrap();
        generate_keyfile(&wrong_keyfile).unwrap();

        encrypt_file(
            &input,
            &encrypted,
            "right-password",
            &EncryptOptions {
                config: VaultConfig::default(),
                keyfile: Some(keyfile),
            },
        )
        .unwrap();

        let err = decrypt_file(
            &encrypted,
            &dir.path().join("plain.out"),
            "right-password",
            &DecryptOptions {
                keyfile: Some(wrong_keyfile),
            },
        )
        .unwrap_err();

        assert!(matches!(err, VaultError::AuthenticationFailed));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("plain.bin.plock");
        let decrypted = dir.path().join("plain.bin.out");

        fs::write(&input, b"secret").unwrap();
        encrypt_file(
            &input,
            &encrypted,
            "right-password",
            &EncryptOptions::default(),
        )
        .unwrap();
        let err = decrypt_file(
            &encrypted,
            &decrypted,
            "wrong-password",
            &DecryptOptions::default(),
        )
        .unwrap_err();

        assert!(matches!(err, VaultError::AuthenticationFailed));
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("plain.bin.plock");
        let decrypted = dir.path().join("plain.bin.out");

        fs::write(&input, b"secret").unwrap();
        encrypt_file(
            &input,
            &encrypted,
            "right-password",
            &EncryptOptions::default(),
        )
        .unwrap();

        let mut bytes = fs::read(&encrypted).unwrap();
        let idx = bytes.len() - 8;
        bytes[idx] ^= 0x40;
        fs::write(&encrypted, &bytes).unwrap();

        let err = decrypt_file(
            &encrypted,
            &decrypted,
            "right-password",
            &DecryptOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err, VaultError::AuthenticationFailed));
    }

    #[test]
    fn legacy_extension_still_maps_to_original_name() {
        let legacy = PathBuf::from("example.txt.rvault");
        let current = PathBuf::from("example.txt.plock");

        assert_eq!(default_decrypted_output_path(&legacy), PathBuf::from("example.txt"));
        assert_eq!(default_decrypted_output_path(&current), PathBuf::from("example.txt"));
    }

    #[test]
    fn oversized_keyfile_is_rejected() {
        let dir = tempdir().unwrap();
        let keyfile = dir.path().join("oversized.key");
        let file = File::create(&keyfile).unwrap();
        file.set_len(MAX_KEYFILE_SIZE_BYTES + 1).unwrap();

        let err = hash_keyfile(&keyfile).unwrap_err();
        assert!(matches!(err, VaultError::KeyfileTooLarge(_)));
    }

    #[test]
    fn persist_noclobber_rejects_existing_output() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("existing.bin");
        fs::write(&output, b"existing").unwrap();

        let mut temp = Builder::new().prefix(".plock-test-").tempfile_in(dir.path()).unwrap();
        temp.as_file_mut().write_all(b"replacement").unwrap();
        temp.as_file_mut().sync_all().unwrap();

        let err = persist_tempfile_noclobber(temp, &output).unwrap_err();
        assert!(matches!(err, VaultError::OutputExists(_)));
        assert_eq!(fs::read(&output).unwrap(), b"existing");
    }

    #[test]
    fn cleanup_stale_tempfiles_removes_tracked_plaintext_tempfiles() {
        let dir = tempdir().unwrap();
        let mut temp = create_tracked_tempfile(dir.path(), TEMP_FILE_PREFIX).unwrap();
        temp.as_file_mut().write_all(b"plaintext").unwrap();
        temp.as_file_mut().sync_all().unwrap();

        let (file, path) = temp.keep().unwrap();
        drop(file);

        let removed = cleanup_stale_tempfiles().unwrap();
        assert_eq!(removed, 1);
        assert!(!path.exists());
    }

    #[test]
    fn decrypt_still_supports_v3_files() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("legacy-v3.plock");
        let decrypted = dir.path().join("plain.out");

        fs::write(&input, b"legacy data".repeat(1024)).unwrap();
        encrypt_file_v3_for_test(
            &input,
            &encrypted,
            "compat-password",
            &EncryptOptions::default(),
        )
        .unwrap();

        decrypt_file(
            &encrypted,
            &decrypted,
            "compat-password",
            &DecryptOptions::default(),
        )
        .unwrap();

        assert_eq!(read_magic_and_version(&encrypted).unwrap(), VERSION_V3);
        assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());
    }

    #[test]
    fn inspect_vault_reports_expected_summary_for_v3_and_v4() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let v3_path = dir.path().join("legacy-v3.plock");
        let v4_path = dir.path().join("current-v4.plock");
        let keyfile = dir.path().join("vault.key");

        fs::write(&input, b"summary-test-data".repeat(512)).unwrap();
        generate_keyfile(&keyfile).unwrap();

        encrypt_file_v3_for_test(
            &input,
            &v3_path,
            "inspect-password",
            &EncryptOptions {
                config: VaultConfig::default(),
                keyfile: Some(keyfile.clone()),
            },
        )
        .unwrap();
        encrypt_file(
            &input,
            &v4_path,
            "inspect-password",
            &EncryptOptions {
                config: VaultConfig::default(),
                keyfile: Some(keyfile),
            },
        )
        .unwrap();

        let v3 = inspect_vault(&v3_path).unwrap();
        let v4 = inspect_vault(&v4_path).unwrap();

        assert_eq!(v3.version, VERSION_V3);
        assert_eq!(v3.cipher, "AES-256-GCM");
        assert!(v3.keyfile_required);
        assert!(!v3.supports_rewrap);

        assert_eq!(v4.version, VERSION_V4);
        assert_eq!(v4.kdf, "Argon2id");
        assert!(v4.keyfile_required);
        assert!(v4.supports_rewrap);
        assert_eq!(v4.chunk_size as usize, VaultConfig::default().chunk_size);
    }

    #[test]
    fn verify_vault_distinguishes_valid_and_invalid_credentials() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("verify.plock");
        let keyfile = dir.path().join("vault.key");
        let wrong_keyfile = dir.path().join("wrong.key");

        fs::write(&input, b"verify-me".repeat(2048)).unwrap();
        generate_keyfile(&keyfile).unwrap();
        generate_keyfile(&wrong_keyfile).unwrap();

        encrypt_file(
            &input,
            &encrypted,
            "verify-password",
            &EncryptOptions {
                config: VaultConfig::default(),
                keyfile: Some(keyfile.clone()),
            },
        )
        .unwrap();

        verify_vault(&encrypted, "verify-password", Some(&keyfile)).unwrap();

        let wrong_password = verify_vault(&encrypted, "wrong-password", Some(&keyfile)).unwrap_err();
        assert!(matches!(wrong_password, VaultError::AuthenticationFailed));

        let wrong_key = verify_vault(&encrypted, "verify-password", Some(&wrong_keyfile)).unwrap_err();
        assert!(matches!(wrong_key, VaultError::AuthenticationFailed));
    }

    #[test]
    fn rewrap_v4_rotates_credentials_without_reencrypting_payload() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let encrypted = dir.path().join("original.plock");
        let rotated = dir.path().join("rotated.plock");
        let decrypted = dir.path().join("rotated.out");
        let old_keyfile = dir.path().join("old.key");
        let new_keyfile = dir.path().join("new.key");

        fs::write(&input, b"rewrap-data".repeat(4096)).unwrap();
        generate_keyfile(&old_keyfile).unwrap();
        generate_keyfile(&new_keyfile).unwrap();

        encrypt_file(
            &input,
            &encrypted,
            "old-password",
            &EncryptOptions {
                config: VaultConfig::default(),
                keyfile: Some(old_keyfile.clone()),
            },
        )
        .unwrap();

        rewrap_vault(
            &encrypted,
            &rotated,
            "old-password",
            Some(&old_keyfile),
            "new-password",
            Some(&new_keyfile),
        )
        .unwrap();

        let old_credentials = decrypt_file(
            &rotated,
            &dir.path().join("wrong.out"),
            "old-password",
            &DecryptOptions {
                keyfile: Some(old_keyfile.clone()),
            },
        )
        .unwrap_err();
        assert!(matches!(old_credentials, VaultError::AuthenticationFailed));

        decrypt_file(
            &rotated,
            &decrypted,
            "new-password",
            &DecryptOptions {
                keyfile: Some(new_keyfile),
            },
        )
        .unwrap();

        assert_eq!(fs::read(&decrypted).unwrap(), fs::read(&input).unwrap());
    }

    #[test]
    fn rewrap_rejects_legacy_versions() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.bin");
        let legacy = dir.path().join("legacy-v3.plock");
        let rotated = dir.path().join("legacy-rotated.plock");

        fs::write(&input, b"legacy".repeat(1024)).unwrap();
        encrypt_file_v3_for_test(
            &input,
            &legacy,
            "legacy-password",
            &EncryptOptions::default(),
        )
        .unwrap();

        let err = rewrap_vault(
            &legacy,
            &rotated,
            "legacy-password",
            None,
            "new-password",
            None,
        )
        .unwrap_err();

        assert!(matches!(err, VaultError::UnsupportedRewrapVersion(VERSION_V3)));
    }
}
