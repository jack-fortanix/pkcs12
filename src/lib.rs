/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![deny(warnings)]

extern crate yasna;
extern crate mbedtls;

#[cfg(feature="rc2_encryption")]
extern crate rc2;
#[cfg(feature="rc2_encryption")]
extern crate block_modes;

use std::result::Result as StdResult;

use yasna::{BERDecodable, BERReader, BERReaderSeq, ASN1Result, ASN1Error, ASN1ErrorKind, Tag};
use yasna::models::ObjectIdentifier;
use yasna::tags::*;

use mbedtls::hash::{Type as MdType, pbkdf_pkcs12};
use mbedtls::cipher::{Cipher, Decryption, Traditional, Fresh};
use mbedtls::cipher::raw::{CipherId, CipherMode};
use mbedtls::Error as MbedtlsError;
use mbedtls::pk::Pk;
use mbedtls::x509::Certificate;

const PKCS7_DATA              : &[u64] = &[1, 2, 840, 113549, 1, 7, 1];
const PKCS7_ENCRYPTED_DATA    : &[u64] = &[1, 2, 840, 113549, 1, 7, 6];

const PKCS9_FRIENDLY_NAME     : &[u64] = &[1, 2, 840, 113549, 1, 9, 20];
const PKCS9_X509_CERT         : &[u64] = &[1, 2, 840, 113549, 1, 9, 22, 1];

const PKCS12_BAG_KEY          : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 1];
const PKCS12_BAG_PKCS8_KEY    : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 2];
const PKCS12_BAG_CERT         : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 3];
/*
const PKCS12_BAG_CRL          : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 4];
const PKCS12_BAG_SECRET       : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 5];
const PKCS12_BAG_SAFE_CONTENT : &[u64] = &[1, 2, 840, 113549, 1, 12, 10, 1, 6];
*/

const PKCS12_PBE_SHA_3DES_168 : &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 3];
const PKCS12_PBE_SHA_3DES_112 : &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 4];
const PKCS12_PBE_SHA_RC2_128  : &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 5];
const PKCS12_PBE_SHA_RC2_40   : &[u64] = &[1, 2, 840, 113549, 1, 12, 1, 6];

fn read_struct_from_bytes<T: BERDecodable>(der: &[u8]) -> ASN1Result<T> {
    yasna::decode_der::<T>(der)
}

fn read_struct<T: BERDecodable>(reader: &mut BERReaderSeq) -> ASN1Result<T> {
    read_struct_from_bytes(&reader.next().read_der().unwrap())
}

fn read_string_type(der: &[u8]) -> ASN1Result<String> {

    yasna::parse_der(der, |reader| {
        let tag = reader.lookahead_tag().unwrap();

        match tag {
            TAG_UTF8STRING => reader.read_utf8string(),
            TAG_PRINTABLESTRING => reader.read_printable_string(),
            TAG_NUMERICSTRING => reader.read_numeric_string(),

            // Support reading some string types not supported by yasna...

            TAG_IA5STRING => {
                // IA5 is (roughly speaking) equivalent to ASCII
                reader.read_tagged_implicit(TAG_IA5STRING, |reader| {
                    let bytes = reader.read_bytes().unwrap();
                    Ok(String::from_utf8(bytes).unwrap())
                })
            }

            TAG_BMPSTRING => {
                reader.read_tagged_implicit(TAG_BMPSTRING, |reader| {
                    let bytes = reader.read_bytes().unwrap();
                    if bytes.len() % 2 != 0 {
                        return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
                    }

                    let utf16 = bytes.chunks(2).map(|c| (c[0] as u16) * 256 + c[1] as u16).collect::<Vec<_>>();

                    Ok(String::from_utf16_lossy(&utf16))
                })
            }

            // Some unknown string type...
            _ => { Err(ASN1Error::new(ASN1ErrorKind::Invalid)) }
        }
    })
}

fn read_seq_of<T: BERDecodable + std::fmt::Debug>(der: &[u8]) -> ASN1Result<Vec<T>> {

    let mut result = Vec::new();

    yasna::parse_der(der, |reader| {
        reader.read_sequence_of(|reader| {
            if let Ok(data) = reader.read_der() {
                let v : T = yasna::decode_der(&data).unwrap();
                result.push(v);
                return Ok(());
            }
            else {
                return Err(ASN1Error::new(ASN1ErrorKind::Eof));
            }
        }).unwrap();
        return Ok(());
    }).unwrap();

    Ok(result)
}

fn read_set_of<T: BERDecodable + std::fmt::Debug>(der: &[u8]) -> ASN1Result<Vec<T>> {

    let mut result = Vec::new();

    yasna::parse_der(der, |reader| {
        reader.read_set_of(|reader| {
            if let Ok(data) = reader.read_der() {
                let v : T = yasna::decode_der(&data).unwrap();
                result.push(v);
                return Ok(());
            }
            else {
                return Err(ASN1Error::new(ASN1ErrorKind::Eof));
            }
        }).unwrap();
        return Ok(());
    }).unwrap();

    Ok(result)
}

#[derive(Debug)]
pub enum Pkcs12Error {
    ASN1(ASN1Error),
    Crypto(MbedtlsError),
    Custom(String),
}

impl From<ASN1Error> for Pkcs12Error {
    fn from(error: ASN1Error) -> Pkcs12Error {
        Pkcs12Error::ASN1(error)
    }
}

impl From<MbedtlsError> for Pkcs12Error {
    fn from(error: MbedtlsError) -> Pkcs12Error {
        Pkcs12Error::Crypto(error)
    }
}

pub type Pkcs12Result<T> = StdResult<T, Pkcs12Error>;

#[derive(Debug, Clone)]
pub struct AlgorithmIdentifier {
    algo: ObjectIdentifier,
    params: Vec<u8>,
}

impl BERDecodable for AlgorithmIdentifier {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let algo = reader.next().read_oid().unwrap();
            let params = reader.next().read_der().ok().unwrap_or(Vec::new());

            Ok(AlgorithmIdentifier { algo, params })
        })
    }
}

#[derive(Debug, Clone)]
pub struct Attribute {
    id: ObjectIdentifier,
    values: Vec<Vec<u8>>, // SET of opaque blob
}

impl BERDecodable for Attribute {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let id = reader.next().read_oid().unwrap();
            let values = reader.next().collect_set_of(|reader| { reader.read_der() }).unwrap();

            Ok(Attribute { id, values })
        })
    }
}

#[derive(Debug, Clone)]
pub struct DigestInfo {
    algo: AlgorithmIdentifier,
    digest: Vec<u8>
}

impl BERDecodable for DigestInfo {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let algo = read_struct::<AlgorithmIdentifier>(reader).unwrap();
            let digest = reader.next().read_bytes().unwrap();

            Ok(DigestInfo { algo, digest })
        })
    }
}

#[derive(Debug, Clone)]
pub struct MacData {
    digest: DigestInfo,
    salt: Vec<u8>,
    iterations: u32
}

impl BERDecodable for MacData {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let digest = read_struct::<DigestInfo>(reader).unwrap();
            let salt = reader.next().read_bytes().unwrap();
            // XXX iterations has default value 1
            let iterations = reader.next().read_u32().unwrap();

            Ok(MacData { digest, salt, iterations })
        })
    }
}

#[derive(Debug, Clone)]
pub struct ContentInfo {
    oid: ObjectIdentifier,
    contents: Vec<ContentInfoContents>,
}

impl BERDecodable for ContentInfo {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let oid = reader.next().read_oid().unwrap();
            let contents = reader.next().read_tagged(Tag::context(0), |reader| { reader.read_bytes() }).unwrap();
            let contents = read_seq_of::<ContentInfoContents>(&contents).unwrap();
            Ok(ContentInfo { oid, contents })
        })
    }
}

#[derive(Debug, Clone)]
pub enum ContentInfoContents {
    Data(SafeContents),
    EncryptedData(EncryptedContent),
}

impl BERDecodable for ContentInfoContents {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {

        let r = reader.read_sequence(|reader| {
            let oid = reader.next().read_oid().unwrap();
            let blob = reader.next().read_tagged(Tag::context(0), |reader| { reader.read_der() }).unwrap();
            Ok((oid, blob))
        }).unwrap();

        if r.0 == ObjectIdentifier::from_slice(PKCS7_DATA) {
            // Wrapped in an OCTET STRING
            let blob = yasna::parse_der(&r.1, |reader| reader.read_bytes()).unwrap();
            let sc = read_struct_from_bytes::<SafeContents>(&blob).unwrap();
            Ok(ContentInfoContents::Data(sc))
        }
        else if r.0 == ObjectIdentifier::from_slice(PKCS7_ENCRYPTED_DATA) {
            let ed = read_struct_from_bytes::<EncryptedContent>(&r.1).unwrap();
            Ok(ContentInfoContents::EncryptedData(ed))
        }
        else {
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedContent {
    version: u32,
    content_info: EncryptedContentInfo,
}

impl BERDecodable for EncryptedContent {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let version = reader.next().read_u32().unwrap();
            let content_info = read_struct::<EncryptedContentInfo>(reader).unwrap();
            Ok(EncryptedContent { version, content_info })
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedContentInfo {
    content_type: ObjectIdentifier,
    encryption_algo: AlgorithmIdentifier,
    encrypted_content: Vec<u8>,
}

impl BERDecodable for EncryptedContentInfo {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let content_type = reader.next().read_oid().unwrap();
            let encryption_algo = read_struct::<AlgorithmIdentifier>(reader).unwrap();
            let encrypted_content = reader.next().read_tagged_implicit(Tag::context(0), |reader| { reader.read_bytes() }).unwrap();
            Ok(EncryptedContentInfo { content_type, encryption_algo, encrypted_content })
        })
    }
}

#[derive(Debug, Clone)]
pub struct Pkcs12Cert {
    cert_type: ObjectIdentifier,
    cert_blob: Vec<u8>,
}

impl BERDecodable for Pkcs12Cert {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let cert_type = reader.next().read_oid().unwrap();
            let cert_blob = reader.next().read_tagged(Tag::context(0), |reader| { reader.read_bytes() }).unwrap();
            Ok(Pkcs12Cert { cert_type, cert_blob })
        })
    }
}

#[derive(Debug, Clone)]
pub struct CertBag {
    certs: Vec<Certificate>,
}

impl BERDecodable for CertBag {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let blob = reader.read_der().unwrap();

        let pkcs12cert = read_struct_from_bytes::<Pkcs12Cert>(&blob).unwrap();

        let mut certs = Vec::new();
        if pkcs12cert.cert_type == ObjectIdentifier::from_slice(PKCS9_X509_CERT) {
            certs.push(Certificate::from_der(&pkcs12cert.cert_blob).unwrap());
        }

        Ok(CertBag { certs })
    }
}

#[derive(Debug, Clone)]
pub struct KeyBag {
    pkcs8: Vec<u8>,
}

impl BERDecodable for KeyBag {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        let key = reader.read_der().unwrap();
        Ok(KeyBag { pkcs8: key })
    }
}

#[derive(Debug, Clone)]
pub struct SafeContents(Vec<SafeBag>);

impl BERDecodable for SafeContents {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        Ok(SafeContents(read_seq_of::<SafeBag>(&reader.read_der().unwrap()).unwrap()))
    }
}

#[derive(Debug, Clone)]
pub enum SafeBagContents {
    Key(KeyBag),
    EncryptedPkcs8(Vec<u8>),
    Pkcs8(Vec<u8>),
    Cert(CertBag),
    SafeContents(SafeContents),
    UnknownBlob(Vec<u8>),
    // XXX CRL and Secret bags not supported
    //Crl(CrlBag),
    //Secret(SecretBag),
}

#[derive(Debug, Clone)]
pub struct SafeBag {
    bag_id: ObjectIdentifier,
    bag_value: SafeBagContents,
    bag_attributes: Vec<Attribute>,
}

impl SafeBag {

    fn friendly_name(&self) -> Pkcs12Result<Vec<String>> {

        let mut names = Vec::new();

        let friendly_name = ObjectIdentifier::from_slice(PKCS9_FRIENDLY_NAME);
        for attr in &self.bag_attributes {
            // Friendly name is a SET OF <STRING> for some mostly arbitrary string type
            if attr.id == friendly_name {

                for v in &attr.values {

                    // Ignore things we cannot decode
                    if let Ok(s) = read_string_type(v) {
                        names.push(s);
                    }
                }
            }
        }

        Ok(names)
    }
}

impl BERDecodable for SafeBag {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let bag_id = reader.next().read_oid().unwrap();
            let bag_blob = reader.next().read_tagged(Tag::context(0), |reader| { reader.read_der() }).unwrap();

            let mut bag_attributes = Vec::new();
            if let Ok(attr) = reader.next().read_der() {
                bag_attributes = read_set_of::<Attribute>(&attr).unwrap();
            }

            let bag_value =
                if bag_id == ObjectIdentifier::from_slice(PKCS12_BAG_KEY) {
                    SafeBagContents::Key(read_struct_from_bytes(&bag_blob).unwrap())
                } else if bag_id == ObjectIdentifier::from_slice(PKCS12_BAG_PKCS8_KEY) {
                    SafeBagContents::EncryptedPkcs8(bag_blob)
                } else if bag_id == ObjectIdentifier::from_slice(PKCS12_BAG_CERT) {
                    SafeBagContents::Cert(read_struct_from_bytes(&bag_blob).unwrap())
                } else {
                    SafeBagContents::UnknownBlob(bag_blob)
                };

            Ok(SafeBag { bag_id, bag_value, bag_attributes })
        })
    }
}

#[derive(Debug, Clone)]
pub struct PFX {
    version: u32,
    authsafe: ContentInfo,
    macdata: Option<MacData>,
}

#[derive(Debug, Clone)]
pub struct Pkcs12PbeParams {
    salt: Vec<u8>,
    iterations: u32,
}

impl BERDecodable for Pkcs12PbeParams {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let salt = reader.next().read_bytes().unwrap();
            let iterations = reader.next().read_u32().unwrap();
            Ok(Pkcs12PbeParams { salt, iterations })
        })
    }
}

// PKCS12 formats PBKDF input as BMP (UCS-16) with trailing NULL
fn format_passphrase_for_pkcs12(passphrase: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for c in passphrase.chars() {
        let mut utf16 = [0u16; 2];
        let utf16 = c.encode_utf16(&mut utf16);

        for u in utf16 {
            v.push((*u >> 8) as u8);
            v.push((*u & 0xFF) as u8);
        }
    }

    // Now append trailing NULL
    v.push(0x00);
    v.push(0x00);
    v
}

fn decrypt_contents(data: &EncryptedContent, passphrase: &[u8]) -> Pkcs12Result<SafeContents> {
    if data.version != 0 {
        return Err(Pkcs12Error::Custom(format!("Unknown EncryptedContent version {}", data.version)));
    }

    let encryption_algo = &data.content_info.encryption_algo.algo;
    let pbe_params : Pkcs12PbeParams = yasna::decode_der(&data.content_info.encryption_algo.params).unwrap();

    let pt = decrypt_data(&data.content_info.encrypted_content, &pbe_params, encryption_algo, passphrase).unwrap();

    let sc = read_struct_from_bytes::<SafeContents>(&pt).unwrap();
    return Ok(sc);
}

fn decrypt_pkcs8(pkcs8: &[u8], passphrase: &[u8]) -> Pkcs12Result<Vec<u8>> {
    let p8 = yasna::parse_der(pkcs8, |reader| {
        reader.read_sequence(|reader| {

            let alg_id = read_struct_from_bytes::<AlgorithmIdentifier>(&reader.next().read_der().unwrap()).unwrap();
            let pbe_params = read_struct_from_bytes::<Pkcs12PbeParams>(&alg_id.params).unwrap();
            let enc_p8 = reader.next().read_bytes().unwrap();

            decrypt_data(&enc_p8, &pbe_params, &alg_id.algo, passphrase).map_err(|_| ASN1Error::new(ASN1ErrorKind::Invalid))
        })
    }).unwrap();

    Ok(p8)
}

fn decrypt_3des(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Pkcs12Result<Vec<u8>> {
    let cipher = Cipher::<Decryption, Traditional, Fresh>::new(CipherId::Des3, CipherMode::CBC, (key.len()*8) as u32).unwrap();
    let cipher = cipher.set_key_iv(&key, &iv).unwrap();
    let mut plaintext = vec![0; ciphertext.len() + 8];
    let len = cipher.decrypt(&ciphertext, &mut plaintext).unwrap();
    plaintext.truncate(len.0);
    return Ok(plaintext);
}

#[cfg(feature="rc2_encryption")]
fn decrypt_rc2(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Pkcs12Result<Vec<u8>> {
    use block_modes::BlockMode;

    let cipher = block_modes::Cbc::<rc2::Rc2, block_modes::block_padding::Pkcs7>::new_var(&key, &iv)
        .map_err(|e| Pkcs12Error::Custom(format!("{:?}", e))).unwrap();

    let mut pt = ciphertext.to_vec();
    let pt = cipher.decrypt(&mut pt).map_err(|e| Pkcs12Error::Custom(format!("{:?}", e))).unwrap();
    return Ok(pt.to_owned());
}

#[cfg(not(feature="rc2_encryption"))]
fn decrypt_rc2(_ciphertext: &[u8], _key: &[u8], _iv: &[u8]) -> Pkcs12Result<Vec<u8>> {
    return Err(Pkcs12Error::Custom("RC2 not supported in this build".to_owned()));
}

fn decrypt_data(ciphertext: &[u8],
                pbe_params: &Pkcs12PbeParams,
                encryption_algo: &ObjectIdentifier,
                passphrase: &[u8]) -> Pkcs12Result<Vec<u8>> {

    fn parse_encryption_algo(oid: &ObjectIdentifier) -> Pkcs12Result<(&'static str,u32)> {

        if *oid == ObjectIdentifier::from_slice(PKCS12_PBE_SHA_3DES_168) {
            return Ok(("3DES", 192/8))
        } else if *oid == ObjectIdentifier::from_slice(PKCS12_PBE_SHA_3DES_112) {
            return Ok(("3DES", 128/8))
        } else if *oid == ObjectIdentifier::from_slice(PKCS12_PBE_SHA_RC2_128) {
            return Ok(("RC2", 128/8))
        } else if *oid == ObjectIdentifier::from_slice(PKCS12_PBE_SHA_RC2_40) {
            return Ok(("RC2", 40/8))
        } else {
            return Err(Pkcs12Error::Custom(format!("Unknown encryption algo {}", oid)));
        }
    }

    let cipher_info = parse_encryption_algo(encryption_algo).unwrap();

    let cipher_algo = cipher_info.0;
    let key_len = cipher_info.1;

    let mut cipher_key = vec![0; key_len as usize];
    let mut cipher_iv = vec![0; 8]; // Either 3DES or RC2

    pbkdf_pkcs12(MdType::Sha1, passphrase, &pbe_params.salt, 1, pbe_params.iterations, &mut cipher_key).unwrap();
    pbkdf_pkcs12(MdType::Sha1, passphrase, &pbe_params.salt, 2, pbe_params.iterations, &mut cipher_iv).unwrap();

    if cipher_algo == "3DES" {
        return decrypt_3des(ciphertext, &cipher_key, &cipher_iv);
    }
    else if cipher_algo == "RC2" {
        return decrypt_rc2(ciphertext, &cipher_key, &cipher_iv);
    }
    else {
        return Err(Pkcs12Error::Custom(format!("Unknown encryption algo {}", cipher_algo)));
    }
}

impl PFX {
    pub fn parse(data: &[u8]) -> Pkcs12Result<PFX> {
        let pfx : PFX = yasna::decode_der(data).unwrap();

        if pfx.version != 3 {
            return Err(Pkcs12Error::Custom(format!("Unknown PKCS12 version {}", pfx.version)));
        }

        Ok(pfx)
    }

    pub fn decrypt(&self, passphrase: &str) -> Pkcs12Result<PFX> {

        let passphrase = format_passphrase_for_pkcs12(passphrase);

        let mut decrypted = self.clone();

        decrypted.authsafe.contents = decrypted.authsafe.contents.iter().map(
            |data| match data {
                ContentInfoContents::Data(sc) => {

                    fn decrypt_pkcs8_sb(sb: &SafeBag, passphrase: &[u8]) -> SafeBag {

                        if let SafeBagContents::EncryptedPkcs8(p8) = &sb.bag_value {
                            if let Ok(decrypted_p8) = decrypt_pkcs8(&p8, passphrase) {
                                return SafeBag {
                                    bag_id: ObjectIdentifier::from_slice(PKCS12_BAG_KEY),
                                    bag_value: SafeBagContents::Pkcs8(decrypted_p8),
                                    bag_attributes: sb.bag_attributes.clone()
                                }
                            }
                        }

                        return sb.clone();
                    }

                    let d : Vec<SafeBag> = sc.0.iter().map(|p| decrypt_pkcs8_sb(p, &passphrase)).collect::<Vec<_>>();
                    ContentInfoContents::Data(SafeContents(d))
                }
                ContentInfoContents::EncryptedData(ed) => {
                    let decrypted = decrypt_contents(&ed, &passphrase);
                    if let Ok(sc) = decrypted {
                        ContentInfoContents::Data(sc)
                    } else {
                        ContentInfoContents::EncryptedData(ed.clone())
                    }
                }
            }).collect();

        Ok(decrypted)
    }

    pub fn certificates(&self) -> Pkcs12Result<Vec<(Certificate, Vec<String>)>> {
        let mut certificates = Vec::new();

        for content in &self.authsafe.contents {

            if let ContentInfoContents::Data(d) = content {
                for sb in &d.0 {

                    if let SafeBagContents::Cert(cb) = &sb.bag_value {
                        let names = sb.friendly_name().unwrap();
                        for c in &cb.certs {
                            certificates.push((c.clone(), names.clone()));
                        }

                    }
                }
            }
        }

        Ok(certificates)
    }

    pub fn private_keys(&self) -> Pkcs12Result<Vec<(Pk, Vec<String>)>> {
        let mut private_keys = Vec::new();

        for content in &self.authsafe.contents {

            if let ContentInfoContents::Data(d) = content {
                for sb in &d.0 {

                    let names = sb.friendly_name().unwrap();

                    let pkcs8 = match &sb.bag_value {
                        SafeBagContents::Pkcs8(p8) => { Some(p8.clone()) },
                        SafeBagContents::Key(key) => { Some(key.pkcs8.clone()) },
                        _ => { /* not a private key */ None }
                    };

                    if let Some(p8) = pkcs8 {
                        let pk = Pk::from_private_key(&p8, None).unwrap();
                        private_keys.push((pk, names.clone()));
                    }
                }
            }
        }

        Ok(private_keys)
    }

}

impl BERDecodable for PFX {
    fn decode_ber(reader: BERReader) -> ASN1Result<Self> {
        reader.read_sequence(|reader| {
            let version = reader.next().read_u32().unwrap();
            let safe = read_struct::<ContentInfo>(reader).unwrap();
            // XXX MacData is technically optional
            let mac = read_struct::<MacData>(reader).unwrap();

            Ok(PFX { version, authsafe: safe, macdata: Some(mac) })
        })
    }
}

