// Copyright (c) Microsoft. All rights reserved.

use std::convert::AsRef;
use std::ffi::{CStr, CString};
use std::ops::{Deref, Drop};
use std::os::raw::{c_uchar, c_void};
use std::slice;
use std::str;

use error::{Error, ErrorKind};
use hsm_sys::*;
use super::*;

/// Enumerator for CERTIFICATE_TYPE
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CertificateType {
    Unknown,
    Client,
    Server,
    Ca,
}

/// Common HSM functions for Edge
/// create an instance of this to use the HSM common interfaces needed for Edge
///
/// This structure implements traits:
/// - MakeRandom
/// - CreateMasterEncryptionKey
/// - DestroyMasterEncryptionKey
/// - CreateCertificate
/// - Encrypt
/// - Decrypt
///
#[derive(Clone, Debug)]
pub struct Crypto {
    handle: HSM_CLIENT_HANDLE,
    interface: HSM_CLIENT_CRYPTO_INTERFACE_TAG,
}

impl Drop for Crypto {
    fn drop(&mut self) {
        if let Some(f) = self.interface.hsm_client_crypto_destroy {
            unsafe {
                f(self.handle);
            }
        }
        unsafe { hsm_client_crypto_deinit() };
    }
}

impl Crypto {
    /// Create a new Cryptography implementation for the HSM API.
    pub fn new() -> Result<Crypto, Error> {
        let result = unsafe { hsm_client_crypto_init() as isize };
        if result != 0 {
            Err(result)?
        }
        let if_ptr = unsafe { hsm_client_crypto_interface() };
        if if_ptr.is_null() {
            unsafe { hsm_client_crypto_deinit() };
            Err(ErrorKind::NullResponse)?
        }
        let interface = unsafe { *if_ptr };
        if let Some(handle) = interface.hsm_client_crypto_create.map(|f| unsafe { f() }) {
            if handle.is_null() {
                unsafe { hsm_client_crypto_deinit() };
                Err(ErrorKind::NullResponse)?
            }
            Ok(Crypto { handle, interface })
        } else {
            unsafe { hsm_client_crypto_deinit() };
            Err(ErrorKind::NullResponse)?
        }
    }
}

impl Default for Crypto {
    fn default() -> Self {
        Self::new().expect("Default Crypto struct failed to create")
    }
}

impl MakeRandom for Crypto {
    fn get_random_bytes(&self, rand_buffer: &mut [u8]) -> Result<(), Error> {
        let if_fn = self.interface
            .hsm_client_get_random_bytes
            .ok_or(ErrorKind::NoneFn)?;
        let result = unsafe {
            if_fn(
                self.handle,
                rand_buffer.as_ptr() as *mut c_uchar,
                rand_buffer.len(),
            )
        };
        match result {
            0 => Ok(()),
            r => Err(r)?,
        }
    }
}

impl CreateMasterEncryptionKey for Crypto {
    fn create_master_encryption_key(&self) -> Result<(), Error> {
        let if_fn = self.interface
            .hsm_client_create_master_encryption_key
            .ok_or(ErrorKind::NoneFn)?;
        let result = unsafe { if_fn(self.handle) };
        match result {
            0 => Ok(()),
            r => Err(r)?,
        }
    }
}

impl DestroyMasterEncryptionKey for Crypto {
    fn destroy_master_encryption_key(&self) -> Result<(), Error> {
        let if_fn = self.interface
            .hsm_client_destroy_master_encryption_key
            .ok_or(ErrorKind::NoneFn)?;
        let result = unsafe { if_fn(self.handle) };
        match result {
            0 => Ok(()),
            r => Err(r)?,
        }
    }
}

fn make_certification_props(props: &CertificateProperties) -> Result<CERT_PROPS_HANDLE, Error> {
    let handle = unsafe { cert_properties_create() };
    if handle.is_null() {
        return Err(ErrorKind::CertProps)?;
    }
    if unsafe { set_validity_seconds(handle, *props.validity_in_secs()) } != 0 {
        unsafe { cert_properties_destroy(handle) };
        return Err(ErrorKind::CertProps)?;
    }
    CString::new(props.common_name.clone())
        .ok()
        .and_then(|c_common_name| {
            let result = unsafe { set_common_name(handle, c_common_name.as_ptr()) };
            match result {
                0 => Some(()),
                _ => None,
            }
        })
        .ok_or_else(|| {
            unsafe { cert_properties_destroy(handle) };
            ErrorKind::CertProps
        })?;

    let c_cert_type = match *props.certificate_type() {
        CertificateType::Client => CERTIFICATE_TYPE_TAG_CERTIFICATE_TYPE_CLIENT,
        CertificateType::Server => CERTIFICATE_TYPE_TAG_CERTIFICATE_TYPE_SERVER,
        CertificateType::Ca => CERTIFICATE_TYPE_TAG_CERTIFICATE_TYPE_CA,
        _ => CERTIFICATE_TYPE_TAG_CERTIFICATE_TYPE_UNKNOWN,
    };
    let result = unsafe { set_certificate_type(handle, c_cert_type) };
    match result {
        0 => Some(()),
        _ => None,
    }.ok_or_else(|| {
        unsafe { cert_properties_destroy(handle) };
        ErrorKind::CertProps
    })?;

    CString::new(props.issuer_alias.clone())
        .ok()
        .and_then(|c_issuer_alias| {
            let result = unsafe { set_issuer_alias(handle, c_issuer_alias.as_ptr()) };
            match result {
                0 => Some(()),
                _ => None,
            }
        })
        .ok_or_else(|| {
            unsafe { cert_properties_destroy(handle) };
            ErrorKind::CertProps
        })?;

    CString::new(props.alias.clone())
        .ok()
        .and_then(|c_alias| {
            let result = unsafe { set_alias(handle, c_alias.as_ptr()) };
            match result {
                0 => Some(()),
                _ => None,
            }
        })
        .ok_or_else(|| {
            unsafe { cert_properties_destroy(handle) };
            ErrorKind::CertProps
        })?;
    Ok(handle)
}

impl CreateCertificate for Crypto {
    fn create_certificate(
        &self,
        properties: &CertificateProperties,
    ) -> Result<HsmCertificate, Error> {
        let property_handle = make_certification_props(properties)?;
        let if_fn = self.interface
            .hsm_client_create_certificate
            .ok_or(ErrorKind::NoneFn)?;
        let cert_info_handle = unsafe { if_fn(self.handle, property_handle) };
        unsafe { cert_properties_destroy(property_handle) };

        if cert_info_handle.is_null() {
            Err(ErrorKind::NullResponse)?
        } else {
            Ok(HsmCertificate { cert_info_handle })
        }
    }
}

impl GetTrustBundle for Crypto {
    fn get_trust_bundle(&self) -> Result<HsmCertificate, Error> {
        let if_fn = self.interface
            .hsm_client_get_trust_bundle
            .ok_or(ErrorKind::NoneFn)?;
        let cert_info_handle = unsafe { if_fn(self.handle) };
        if cert_info_handle.is_null() {
            Err(ErrorKind::NullResponse)?
        } else {
            Ok(HsmCertificate { cert_info_handle })
        }
    }
}

impl Encrypt for Crypto {
    fn encrypt(
        &self,
        client_id: &[u8],
        plaintext: &[u8],
        passphrase: Option<&[u8]>,
        initialization_vector: &[u8],
    ) -> Result<Buffer, Error> {
        let if_fn = self.interface
            .hsm_client_encrypt_data
            .ok_or(ErrorKind::NoneFn)?;

        let c_client_id = SIZED_BUFFER {
            buffer: client_id.as_ptr() as *mut c_uchar,
            size: client_id.len(),
        };
        let c_plaintext = SIZED_BUFFER {
            buffer: plaintext.as_ptr() as *mut c_uchar,
            size: plaintext.len(),
        };
        let c_initialization_vector = SIZED_BUFFER {
            buffer: initialization_vector.as_ptr() as *mut c_uchar,
            size: initialization_vector.len(),
        };
        let mut encrypted = SIZED_BUFFER {
            buffer: std::ptr::null_mut() as *mut c_uchar,
            size: 0,
        };
        let result = match passphrase {
            Some(pp) => {
                let c_passphrase = SIZED_BUFFER {
                    buffer: pp.as_ptr() as *mut c_uchar,
                    size: pp.len(),
                };
                unsafe {
                    if_fn(
                        self.handle,
                        &c_client_id,
                        &c_plaintext,
                        &c_passphrase,
                        &c_initialization_vector,
                        &mut encrypted,
                    )
                }
            }
            None => unsafe {
                if_fn(
                    self.handle,
                    &c_client_id,
                    &c_plaintext,
                    std::ptr::null(),
                    &c_initialization_vector,
                    &mut encrypted,
                )
            },
        };
        match result {
            0 => Ok(Buffer::new(self.interface, encrypted)),
            r => Err(r)?,
        }
    }
}

impl Decrypt for Crypto {
    fn decrypt(
        &self,
        client_id: &[u8],
        ciphertext: &[u8],
        passphrase: Option<&[u8]>,
        initialization_vector: &[u8],
    ) -> Result<Buffer, Error> {
        let if_fn = self.interface
            .hsm_client_decrypt_data
            .ok_or(ErrorKind::NoneFn)?;

        let c_client_id = SIZED_BUFFER {
            buffer: client_id.as_ptr() as *mut c_uchar,
            size: client_id.len(),
        };
        let c_ciphertext = SIZED_BUFFER {
            buffer: ciphertext.as_ptr() as *mut c_uchar,
            size: ciphertext.len(),
        };
        let c_initialization_vector = SIZED_BUFFER {
            buffer: initialization_vector.as_ptr() as *mut c_uchar,
            size: initialization_vector.len(),
        };
        let mut decrypted = SIZED_BUFFER {
            buffer: std::ptr::null_mut() as *mut c_uchar,
            size: 0,
        };
        let result = match passphrase {
            Some(pp) => {
                let c_passphrase = SIZED_BUFFER {
                    buffer: pp.as_ptr() as *mut c_uchar,
                    size: pp.len(),
                };
                unsafe {
                    if_fn(
                        self.handle,
                        &c_client_id,
                        &c_ciphertext,
                        &c_passphrase,
                        &c_initialization_vector,
                        &mut decrypted,
                    )
                }
            }
            None => unsafe {
                if_fn(
                    self.handle,
                    &c_client_id,
                    &c_ciphertext,
                    std::ptr::null(),
                    &c_initialization_vector,
                    &mut decrypted,
                )
            },
        };
        match result {
            0 => Ok(Buffer::new(self.interface, decrypted)),
            r => Err(r)?,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertificateProperties {
    validity_in_secs: u64,
    common_name: String,
    certificate_type: CertificateType,
    issuer_alias: String,
    alias: String,
    country: Option<String>,
    state: Option<String>,
    locality: Option<String>,
    organization: Option<String>,
    organization_unit: Option<String>,
}

impl CertificateProperties {
    pub fn new(
        validity_in_secs: u64,
        common_name: String,
        certificate_type: CertificateType,
        issuer_alias: String,
        alias: String,
    ) -> Self {
        CertificateProperties {
            validity_in_secs: validity_in_secs,
            common_name,
            certificate_type,
            issuer_alias,
            alias,
            country: None,
            state: None,
            locality: None,
            organization: None,
            organization_unit: None,
        }
    }

    pub fn validity_in_secs(&self) -> &u64 {
        &self.validity_in_secs
    }

    pub fn with_validity_in_secs(mut self, validity_in_secs: u64) -> CertificateProperties {
        self.validity_in_secs = validity_in_secs;
        self
    }

    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    pub fn with_common_name(mut self, common_name: String) -> CertificateProperties {
        self.common_name = common_name;
        self
    }

    pub fn certificate_type(&self) -> &CertificateType {
        &self.certificate_type
    }

    pub fn with_certificate_type(
        mut self,
        certificate_type: CertificateType,
    ) -> CertificateProperties {
        self.certificate_type = certificate_type;
        self
    }

    pub fn country(&self) -> Option<&String> {
        self.country.as_ref()
    }

    pub fn with_country(mut self, country: String) -> CertificateProperties {
        self.country = Some(country);
        self
    }

    pub fn state(&self) -> Option<&String> {
        self.state.as_ref()
    }

    pub fn with_state(mut self, state: String) -> CertificateProperties {
        self.state = Some(state);
        self
    }

    pub fn locality(&self) -> Option<&String> {
        self.locality.as_ref()
    }

    pub fn with_locality(mut self, locality: String) -> CertificateProperties {
        self.locality = Some(locality);
        self
    }

    pub fn organization(&self) -> Option<&String> {
        self.organization.as_ref()
    }

    pub fn with_organization(mut self, organization: String) -> CertificateProperties {
        self.organization = Some(organization);
        self
    }

    pub fn organization_unit(&self) -> Option<&String> {
        self.organization_unit.as_ref()
    }

    pub fn with_organization_unit(mut self, organization_unit: String) -> CertificateProperties {
        self.organization_unit = Some(organization_unit);
        self
    }

    pub fn issuer_alias(&self) -> &String {
        &self.issuer_alias
    }

    pub fn with_issuer_alias(mut self, issuer_alias: String) -> CertificateProperties {
        self.issuer_alias = issuer_alias;
        self
    }

    pub fn alias(&self) -> &String {
        &self.alias
    }

    pub fn with_alias(mut self, alias: String) -> CertificateProperties {
        self.alias = alias;
        self
    }
}

impl Default for CertificateProperties {
    fn default() -> Self {
        CertificateProperties {
            validity_in_secs: 3600,
            common_name: String::from("CN"),
            certificate_type: CertificateType::Client,
            issuer_alias: String::from("device_ca_alias"),
            alias: String::from("module_1"),
            country: Some(String::from("US")),
            state: None,
            locality: None,
            organization: None,
            organization_unit: None,
        }
    }
}

pub enum PrivateKey<T: AsRef<[u8]>> {
    Ref(String),
    Key(T),
}

/// A structure representing a Certificate in the HSM.
#[derive(Debug)]
pub struct HsmCertificate {
    cert_info_handle: CERT_INFO_HANDLE,
}

impl HsmCertificate {
    pub fn pem(&self) -> Result<String, Error> {
        let cert = unsafe {
            CStr::from_ptr(certificate_info_get_certificate(self.cert_info_handle))
                .to_string_lossy()
                .into_owned()
        };
        if cert.is_empty() {
            Err(ErrorKind::NullResponse)?
        }
        Ok(cert)
    }

    pub fn get_private_key(&self) -> Result<(u32, PrivateKey<Vec<u8>>), Error> {
        let mut pk_size: usize = 0;
        let pk = unsafe { certificate_info_get_private_key(self.cert_info_handle, &mut pk_size) };
        if pk_size == 0 || pk.is_null() {
            Err(ErrorKind::NullResponse)?
        } else {
            let private_key =
                unsafe { slice::from_raw_parts(pk as *const c_uchar, pk_size).to_vec() };
            let pk_type = unsafe { certificate_info_private_key_type(self.cert_info_handle) };
            let private_key = match pk_type {
                0 => Ok(PrivateKey::Key(private_key)),
                1 => Ok(PrivateKey::Ref(String::from_utf8(private_key)?)),
                e => Err(Error::from(ErrorKind::PrivateKeyType(e))),
            }?;
            Ok((CRYPTO_ENCODING_TAG_PEM, private_key))
        }
    }
}

impl Drop for HsmCertificate {
    fn drop(&mut self) {
        unsafe { certificate_info_destroy(self.cert_info_handle) };
    }
}

/// When data is returned from the HSM Common interface, it is placed in this struct.
/// This is a buffer owned by the C library.
#[derive(Debug)]
pub struct Buffer {
    interface: HSM_CLIENT_CRYPTO_INTERFACE,
    data: SIZED_BUFFER,
}

impl Buffer {
    fn new(interface: HSM_CLIENT_CRYPTO_INTERFACE, data: SIZED_BUFFER) -> Buffer {
        Buffer { interface, data }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let free_fn = self.interface
            .hsm_client_free_buffer
            .expect("Unknown Free function for Buffer");
        unsafe { free_fn(self.data.buffer as *mut c_void) };
    }
}

impl Deref for Buffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        unsafe { &slice::from_raw_parts(self.data.buffer as *const c_uchar, self.data.size) }
    }
}

#[cfg(test)]
mod tests {
    use std::os::raw::{c_char, c_int, c_uchar, c_void};
    use std::ffi::CString;

    use hsm_sys::*;
    use super::{Buffer, CertificateProperties, Crypto};
    use super::super::{CreateCertificate, CreateMasterEncryptionKey, Decrypt,
                       DestroyMasterEncryptionKey, Encrypt, GetTrustBundle, MakeRandom};

    static TEST_RSA_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIICpDCCAYwCCQCgAJQdOd6dNzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTcwMTIwMTkyNTMzWhcNMjcwMTE4MTkyNTMzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlJ3fRNWm05BRAhgUY7cpzaxHZIORomZaOp2Uua5yv+psdkpv35ExLhKGrUIK1AJLZylnue0ohZfKPFTnoxMHOecnaaXZ9RA25M7XGQvw85ePlGOZKKf3zXw3Ds58GFY6Sr1SqtDopcDuMmDSg/afYVvGHDjb2Fc4hZFip350AADcmjH5SfWuxgptCY2Jl6ImJoOpxt+imWsJCJEmwZaXw+eZBb87e/9PH4DMXjIUFZebShowAfTh/sinfwRkaLVQ7uJI82Ka/icm6Hmr56j7U81gDaF0DhC03ds5lhN7nMp5aqaKeEJiSGdiyyHAescfxLO/SMunNc/eG7iAirY7BAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACU7TRogb8sEbv+SGzxKSgWKKbw+FNgC4Zi6Fz59t+4jORZkoZ8W87NM946wvkIpxbLKuc4F+7nTGHHksyHIiGC3qPpi4vWpqVeNAP+kfQptFoWEOzxD7jQTWIcqYhvssKZGwDk06c/WtvVnhZOZW+zzJKXA7mbwJrfp8VekOnN5zPwrOCumDiRX7BnEtMjqFDgdMgs9ohR5aFsI7tsqp+dToLKaZqBLTvYwCgCJCxdg3QvMhVD8OxcEIFJtDEwm3h9WFFO3ocabCmcMDyXUL354yaZ7RphCBLd06XXdaUU/eV6fOjY6T5ka4ZRJcYDJtjxSG04XPtxswQfrPGGoFhk=\n-----END CERTIFICATE-----";

    extern "C" {
        pub fn malloc(size: usize) -> *mut c_void;
        pub fn memset(s: *mut c_void, c: c_int, size: usize) -> *mut c_void;
        pub fn free(s: *mut c_void);

    }

    unsafe extern "C" fn real_buffer_destroy(b: *mut c_void) {
        free(b);
    }

    fn fake_good_crypto_buffer_free() -> HSM_CLIENT_CRYPTO_INTERFACE {
        HSM_CLIENT_CRYPTO_INTERFACE {
            hsm_client_free_buffer: Some(real_buffer_destroy),
            ..HSM_CLIENT_CRYPTO_INTERFACE::default()
        }
    }

    #[test]
    fn hsm_crypto_data_test() {
        let len = 100;
        let key = unsafe {
            let v = malloc(len);
            memset(v, 32 as c_int, len)
        };
        let buffer = SIZED_BUFFER {
            buffer: key as *mut c_uchar,
            size: len,
        };

        let key2 = Buffer::new(fake_good_crypto_buffer_free(), buffer);

        let slice1 = &key2;

        assert_eq!(slice1.len(), len);
    }

    #[test]
    #[should_panic(expected = "Unknown Free function for Buffer")]
    fn hsm_crypto_free_fn_none() {
        let key = b"0123456789";
        let len = key.len();
        let buffer = SIZED_BUFFER {
            buffer: key.as_ptr() as *mut c_uchar,
            size: len,
        };

        let key2 = Buffer::new(HSM_CLIENT_CRYPTO_INTERFACE::default(), buffer);

        let slice1 = &key2;
        assert_eq!(slice1.len(), len);
        // function will panic on drop.
    }

    unsafe extern "C" fn fake_handle_create_good() -> HSM_CLIENT_HANDLE {
        0_isize as *mut c_void
    }
    unsafe extern "C" fn fake_handle_create_bad() -> HSM_CLIENT_HANDLE {
        1_isize as *mut c_void
    }
    unsafe extern "C" fn fake_random_bytes(
        handle: HSM_CLIENT_HANDLE,
        _buffer: *mut c_uchar,
        _buffer_size: usize,
    ) -> c_int {
        let n = handle as isize;
        if n == 0 {
            0
        } else {
            1
        }
    }
    unsafe extern "C" fn fake_create_master(handle: HSM_CLIENT_HANDLE) -> c_int {
        let n = handle as isize;
        if n == 0 {
            0
        } else {
            1
        }
    }
    unsafe extern "C" fn fake_destroy_master(handle: HSM_CLIENT_HANDLE) -> c_int {
        let n = handle as isize;
        if n == 0 {
            0
        } else {
            1
        }
    }
    unsafe extern "C" fn fake_encrypt(
        handle: HSM_CLIENT_HANDLE,
        _client_id: *const SIZED_BUFFER,
        _plaintext: *const SIZED_BUFFER,
        _passphrase: *const SIZED_BUFFER,
        _initialization_vector: *const SIZED_BUFFER,
        ciphertext: *mut SIZED_BUFFER,
    ) -> c_int {
        let n = handle as isize;
        if n == 0 {
            (*ciphertext).buffer = malloc(DEFAULT_BUF_LEN) as *mut c_uchar;
            (*ciphertext).size = DEFAULT_BUF_LEN;
            0
        } else {
            1
        }
    }
    unsafe extern "C" fn fake_decrypt(
        handle: HSM_CLIENT_HANDLE,
        _client_id: *const SIZED_BUFFER,
        _ciphertext: *const SIZED_BUFFER,
        _passphrase: *const SIZED_BUFFER,
        _initialization_vector: *const SIZED_BUFFER,
        plaintext: *mut SIZED_BUFFER,
    ) -> c_int {
        let n = handle as isize;
        if n == 0 {
            (*plaintext).buffer = malloc(DEFAULT_BUF_LEN) as *mut c_uchar;
            (*plaintext).size = DEFAULT_BUF_LEN;
            0
        } else {
            1
        }
    }

    unsafe extern "C" fn fake_trust_bundle(handle: HSM_CLIENT_HANDLE) -> CERT_INFO_HANDLE {
        let n = handle as isize;
        if n == 0 {
            let cert = CString::new(TEST_RSA_CERT).unwrap();
            let pk = CString::new("1234").unwrap();
            certificate_info_create(
                cert.as_ptr(),
                pk.as_ptr() as *const c_void,
                pk.to_bytes().len() as usize,
                0 as u32,
            )
        } else {
            ::std::ptr::null_mut()
        }
    }

    unsafe extern "C" fn fake_create_cert(
        handle: HSM_CLIENT_HANDLE,
        _certificate_props: CERT_PROPS_HANDLE,
    ) -> CERT_INFO_HANDLE {
        let n = handle as isize;
        if n == 0 {
            let cert = CString::new(TEST_RSA_CERT).unwrap();
            let pk = CString::new("1234").unwrap();
            certificate_info_create(
                cert.as_ptr(),
                pk.as_ptr() as *const c_void,
                pk.to_bytes().len() as usize,
                0 as u32,
            )
        } else {
            ::std::ptr::null_mut()
        }
    }

    unsafe extern "C" fn fake_destroy_cert(_handle: HSM_CLIENT_HANDLE, _alias: *const c_char) {}

    const DEFAULT_BUF_LEN: usize = 10;

    unsafe extern "C" fn fake_handle_destroy(_h: HSM_CLIENT_HANDLE) {}

    fn fake_no_if_hsm_crypto() -> Crypto {
        Crypto {
            handle: unsafe { fake_handle_create_good() },
            interface: HSM_CLIENT_CRYPTO_INTERFACE {
                hsm_client_crypto_create: Some(fake_handle_create_good),
                hsm_client_crypto_destroy: Some(fake_handle_destroy),
                ..HSM_CLIENT_CRYPTO_INTERFACE::default()
            },
        }
    }

    #[test]
    #[should_panic(expected = "HSM API Not Implemented")]
    fn no_random_bytes_api_fail() {
        let hsm_crypto = fake_no_if_hsm_crypto();
        let mut test_array = [0u8; 4];
        let limits = hsm_crypto.get_random_bytes(&mut test_array).unwrap();
        println!("You should never see this print {:?}", limits);
    }

    #[test]
    #[should_panic(expected = "HSM API Not Implemented")]
    fn no_create_master_key_api_fail() {
        let hsm_crypto = fake_no_if_hsm_crypto();
        let result = hsm_crypto.create_master_encryption_key().unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API Not Implemented")]
    fn no_destroy_master_key_api_fail() {
        let hsm_crypto = fake_no_if_hsm_crypto();
        let result = hsm_crypto.destroy_master_encryption_key().unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API Not Implemented")]
    fn no_create_certificate_api_fail() {
        let props = CertificateProperties::default();
        let hsm_crypto = fake_no_if_hsm_crypto();
        let result = hsm_crypto.create_certificate(&props).unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API Not Implemented")]
    fn no_trust_bundle_api_fail() {
        let hsm_crypto = fake_no_if_hsm_crypto();
        let result = hsm_crypto.get_trust_bundle().unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API Not Implemented")]
    fn no_encrypt_api_fail() {
        let client_id = b"client_id";
        let plaintext = b"plaintext";
        let passphrase = b"passphrase";
        let initialization_vector = b"initialization_vector";
        let hsm_crypto = fake_no_if_hsm_crypto();
        let result = hsm_crypto
            .encrypt(
                client_id,
                plaintext,
                Some(passphrase),
                initialization_vector,
            )
            .unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API Not Implemented")]
    fn no_decrypt_api_fail() {
        let client_id = b"client_id";
        let ciphertext = b"ciphertext";
        let passphrase = b"passphrase";
        let initialization_vector = b"initialization_vector";
        let hsm_crypto = fake_no_if_hsm_crypto();
        let result = hsm_crypto
            .encrypt(
                client_id,
                ciphertext,
                Some(passphrase),
                initialization_vector,
            )
            .unwrap();
        println!("You should never see this print {:?}", result);
    }
    fn fake_bad_hsm_crypto() -> Crypto {
        Crypto {
            handle: unsafe { fake_handle_create_bad() },
            interface: HSM_CLIENT_CRYPTO_INTERFACE {
                hsm_client_crypto_create: Some(fake_handle_create_bad),
                hsm_client_crypto_destroy: Some(fake_handle_destroy),
                hsm_client_get_random_bytes: Some(fake_random_bytes),
                hsm_client_create_master_encryption_key: Some(fake_create_master),
                hsm_client_destroy_master_encryption_key: Some(fake_destroy_master),
                hsm_client_create_certificate: Some(fake_create_cert),
                hsm_client_destroy_certificate: Some(fake_destroy_cert),
                hsm_client_encrypt_data: Some(fake_encrypt),
                hsm_client_decrypt_data: Some(fake_decrypt),
                hsm_client_get_trust_bundle: Some(fake_trust_bundle),
                hsm_client_free_buffer: Some(real_buffer_destroy),
            },
        }
    }

    #[test]
    #[should_panic(expected = "HSM API failure occurred")]
    fn hsm_get_random_bytes_errors() {
        let hsm_crypto = fake_bad_hsm_crypto();
        let mut test_array = [0u8; 4];
        let result = hsm_crypto.get_random_bytes(&mut test_array).unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API failure occurred")]
    fn hsm_create_master_encryption_key_errors() {
        let hsm_crypto = fake_bad_hsm_crypto();
        let result = hsm_crypto.create_master_encryption_key().unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API failure occurred")]
    fn hsm_destroy_master_encryption_key_errors() {
        let hsm_crypto = fake_bad_hsm_crypto();
        let result = hsm_crypto.destroy_master_encryption_key().unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API returned an invalid null response")]
    fn hsm_create_certificate_errors() {
        let hsm_crypto = fake_bad_hsm_crypto();
        let props = CertificateProperties::default();

        let result = hsm_crypto.create_certificate(&props).unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API returned an invalid null response")]
    fn hsm_get_trust_bundle_errors() {
        let hsm_crypto = fake_bad_hsm_crypto();
        let result = hsm_crypto.get_trust_bundle().unwrap();
        println!("You should never see this print {:?}", result);
    }

    #[test]
    #[should_panic(expected = "HSM API failure occurred")]
    fn hsm_encrypt_errors() {
        let hsm_crypto = fake_bad_hsm_crypto();
        let result = hsm_crypto
            .encrypt(b"client_id", b"plaintext", None, b"init_vector")
            .unwrap();
        println!("You should never see this print {:?}", result);
    }
    #[test]
    #[should_panic(expected = "HSM API failure occurred")]
    fn hsm_decrypt_errors() {
        let hsm_crypto = fake_bad_hsm_crypto();
        let result = hsm_crypto
            .decrypt(b"client_id", b"ciphertext", None, b"init_vector")
            .unwrap();
        println!("You should never see this print {:?}", result);
    }

    fn fake_good_hsm_crypto() -> Crypto {
        Crypto {
            handle: unsafe { fake_handle_create_good() },
            interface: HSM_CLIENT_CRYPTO_INTERFACE {
                hsm_client_crypto_create: Some(fake_handle_create_good),
                hsm_client_crypto_destroy: Some(fake_handle_destroy),
                hsm_client_get_random_bytes: Some(fake_random_bytes),
                hsm_client_create_master_encryption_key: Some(fake_create_master),
                hsm_client_destroy_master_encryption_key: Some(fake_destroy_master),
                hsm_client_create_certificate: Some(fake_create_cert),
                hsm_client_destroy_certificate: Some(fake_destroy_cert),
                hsm_client_encrypt_data: Some(fake_encrypt),
                hsm_client_decrypt_data: Some(fake_decrypt),
                hsm_client_get_trust_bundle: Some(fake_trust_bundle),
                hsm_client_free_buffer: Some(real_buffer_destroy),
            },
        }
    }

    #[test]
    fn hsm_success() {
        let hsm_crypto = fake_good_hsm_crypto();

        let mut test_array = [0u8, 4];
        let result_random_bytes = hsm_crypto.get_random_bytes(&mut test_array).unwrap();

        assert_eq!(result_random_bytes, ());

        let master_key = hsm_crypto.create_master_encryption_key().unwrap();

        assert_eq!(master_key, ());

        let destroy_key = hsm_crypto.destroy_master_encryption_key().unwrap();

        assert_eq!(destroy_key, ());

        let props = CertificateProperties::default();
        let _new_cert = hsm_crypto.create_certificate(&props).unwrap();

        let crypt1 = hsm_crypto
            .encrypt(b"client_id", b"plaintext", None, b"init_vector")
            .unwrap();
        let crypt2 = hsm_crypto
            .encrypt(
                b"client_id",
                b"plaintext",
                Some(b"passcode"),
                b"init_vector",
            )
            .unwrap();

        assert_eq!(crypt1.len(), DEFAULT_BUF_LEN);
        assert_eq!(crypt2.len(), DEFAULT_BUF_LEN);

        let plain1 = hsm_crypto
            .decrypt(b"client_id", b"ciphertext", None, b"init_vector")
            .unwrap();
        let plain2 = hsm_crypto
            .decrypt(
                b"client_id",
                b"ciphertext",
                Some(b"passcode"),
                b"init_vector",
            )
            .unwrap();

        assert_eq!(plain1.len(), DEFAULT_BUF_LEN);
        assert_eq!(plain2.len(), DEFAULT_BUF_LEN);
    }

}