use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::constants::{CapabilityType, tss::TPM2_PERSISTENT_FIRST};
use tss_esapi::handles::{
    NvIndexHandle, NvIndexTpmHandle, ObjectHandle, PersistentTpmHandle, TpmHandle,
};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{NvAuth, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Auth, CapabilityData, CreatePrimaryKeyResult, Data, HashScheme, MaxNvBuffer, NvPublicBuilder,
    PublicKeyRsa, RsaDecryptionScheme, RsaExponent,
};
use tss_esapi::tss2_esys::TPM2_HANDLE;
use tss_esapi::utils::create_unrestricted_encryption_decryption_rsa_public;
use tss_esapi::{
    Context,
    handles::KeyHandle,
    interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
};

use std::{
    convert::{TryFrom, TryInto},
    str::from_utf8,
};

pub fn get_persistent_handler() -> PersistentTpmHandle {
    // Create persistent TPM handle with
    PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x00, 0x00, 0x01]))
        .expect("Failed to create persistent tpm handle")
}

fn persist_primary(context: &mut Context, primary_key_handle: KeyHandle) -> ObjectHandle {
    let persistent = Persistent::Persistent(get_persistent_handler());

    // the tpm evict control command is the same for make an object persisten or remove it
    // from persistency (yea!!!)
    context.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.evict_control(Provision::Owner, primary_key_handle.into(), persistent)
            .expect("Failed to make the transient_object_handle handle persistent")
    })
}

pub fn remove_persitent_handle(context: &mut Context, persistent_tpm_handle: PersistentTpmHandle) {
    if let Some(handle) = find_persistent_handle(context, persistent_tpm_handle) {
        println!("Evict control of stored key {:?}", handle);

        context.execute_with_session(Some(AuthSession::Password), |context| {
            context
                .evict_control(
                    Provision::Owner,
                    handle,
                    Persistent::Persistent(persistent_tpm_handle),
                )
                .expect("Failed to evict persistent handle");
        });
    } else {
        println!("Nothing to evict");
    }
}

/// There are different persistent slot, try to find our hardcoded
pub fn find_persistent_handle(
    ctx: &mut Context,
    persistent_tpm_handle: PersistentTpmHandle,
) -> Option<ObjectHandle> {
    let mut property = TPM2_PERSISTENT_FIRST;

    while let Ok((capability_data, more_data_available)) =
        ctx.get_capability(CapabilityType::Handles, property, 1)
    {
        if let CapabilityData::Handles(persistent_handles) = capability_data
            && let Some(&retrieved_persistent_handle) = persistent_handles.first()
        {
            if retrieved_persistent_handle == persistent_tpm_handle.into() {
                let handle = ctx
                    .tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                    .expect("Failed to retrieve handle from TPM");

                return Some(handle);
            }

            if more_data_available {
                property = TPM2_HANDLE::from(retrieved_persistent_handle) + 1;
            }
        }

        if !more_data_available {
            return None;
        }
    }

    None
}

pub fn create_primary_encyrpt_decrypt(context: &mut Context) -> CreatePrimaryKeyResult {
    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                create_unrestricted_encryption_decryption_rsa_public(
                    RsaKeyBits::Rsa2048, // NOTE: with Rsa 4096 fail
                    RsaExponent::default(),
                )
                .unwrap(),
                None,
                None,
                None,
                None,
            )
        })
        .unwrap()
}

pub fn create_and_persist(context: &mut Context) -> KeyHandle {
    let encrypt_primary = create_primary_encyrpt_decrypt(context);
    persist_primary(context, encrypt_primary.key_handle);

    encrypt_primary.key_handle
}

pub fn list_primary(context: &mut Context) -> Option<KeyHandle> {
    let handler = get_persistent_handler();
    let found = find_persistent_handle(context, handler);

    if found.is_none() {
        println!("No primary key stored in persistent handle");
        return None;
    }

    context
        .flush_context(found.unwrap())
        .expect("Call to flush_context failed");

    Some(found.unwrap().into())
}

pub fn encrypt(context: &mut Context, plain_text: Vec<u8>) -> Vec<u8> {
    let handler = get_persistent_handler();
    let encrypt_primary: KeyHandle = find_persistent_handle(context, handler).unwrap().into();

    let data_to_encrypt =
        PublicKeyRsa::try_from(plain_text).expect("Failed to create buffer for data to encrypt.");

    // To encrypt data to a key, we only need it's public component. We demonstrate how
    // to load that public component into a TPM and then encrypt to it.
    let encrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            ctx.rsa_encrypt(
                encrypt_primary,
                data_to_encrypt.clone(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                Data::default(),
            )
        })
        .unwrap();

    encrypted_data.to_vec()
}

pub fn decrypt(context: &mut Context, cypher_text: Vec<u8>) -> Vec<u8> {
    let handler = get_persistent_handler();
    let encrypt_primary: KeyHandle = find_persistent_handle(context, handler).unwrap().into();

    let decrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            ctx.rsa_decrypt(
                encrypt_primary,
                cypher_text.try_into().unwrap(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha256)),
                Data::default(),
            )
        })
        .unwrap();

    decrypted_data.value().to_vec()
}

pub fn test_aes_gcm(context: &mut Context) {
    // Generate key random
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);

    // The nonce should be shared
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let parsed = nonce.to_vec();

    // encrypt message
    let plain_text = "miao miao".as_bytes().to_vec();
    let ciphered_msg = cipher.encrypt(&nonce, plain_text.as_ref()).unwrap();

    // encrypt the aes key with tpm
    let ciphered_key = encrypt(context, key.to_vec());

    // write down the encrypted key to fs
    let _ = std::fs::write("encrypted.key", ciphered_key);

    // read encrypted key from fs
    let encrypted_data = std::fs::read("encrypted.key").unwrap();

    // decrypt aes key with tpm
    let decrypted_key = decrypt(context, encrypted_data);

    // create new cipher from
    let cipher_2 = Aes256Gcm::new(decrypted_key.as_slice().into());
    let nonce_array: [u8; 12] = parsed.try_into().unwrap();
    let original_msg = cipher_2
        .decrypt(&nonce_array.into(), ciphered_msg.as_slice())
        .unwrap();

    println!("Original message: {}", from_utf8(&original_msg).unwrap());
}

// TODO: choose wisely
const NV_INDEX: u32 = 0x0140_0000; // Middle of owner range
pub const NV_SIZE: usize = 40 * 12;

pub fn get_nv_index_handle(ctx: &mut Context) -> anyhow::Result<NvIndexHandle> {
    let nv_index_tpm_handle = NvIndexTpmHandle::new(NV_INDEX)?;

    // Check if it exists by trying to query capabilities
    let mut property = 0x01000000u32; // Start of NV index range
    let mut exists = false;

    while let Ok((capability_data, more)) =
        ctx.get_capability(CapabilityType::Handles, property, 100)
    {
        if let CapabilityData::Handles(handles) = capability_data {
            if handles.iter().any(|&h| TPM2_HANDLE::from(h) == NV_INDEX) {
                exists = true;
                break;
            }
            if let Some(&last) = handles.last() {
                property = TPM2_HANDLE::from(last) + 1;
            }
        }
        if !more {
            break;
        }
    }

    if exists {
        // Index exists, get proper handle
        let handle = ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_index_tpm_handle))?;
        Ok(handle.try_into()?)
    } else {
        // Create new index
        let attrs = NvIndexAttributesBuilder::new()
            .with_owner_read(true)
            .with_owner_write(true)
            .build()?;

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attrs)
            .with_data_area_size(NV_SIZE)
            .build()?;

        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.nv_define_space(Provision::Owner, None, nv_public)
        })?;

        // Get proper handle after creation
        let handle = ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_index_tpm_handle))?;
        Ok(handle.try_into()?)
    }
}

pub fn nv_write_key(
    ctx: &mut Context,
    nv_handle: NvIndexHandle,
    key: &[u8; NV_SIZE],
) -> anyhow::Result<()> {
    let buffer = MaxNvBuffer::try_from(key.as_ref())?;

    ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.nv_write(NvAuth::Owner, nv_handle, buffer, 0)
    })?;

    Ok(())
}

pub fn nv_read_key(ctx: &mut Context, nv_handle: NvIndexHandle) -> anyhow::Result<[u8; NV_SIZE]> {
    let data = ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
        ctx.nv_read(NvAuth::Owner, nv_handle, NV_SIZE as u16, 0)
    })?;

    let buf = data.value();
    let vec = buf.to_vec();
    if vec.len() != NV_SIZE {
        anyhow::bail!("expected {} bytes got {}", NV_SIZE, vec.len())
    }
    let mut out = [0u8; NV_SIZE];
    out.copy_from_slice(&vec);
    Ok(out)
}
