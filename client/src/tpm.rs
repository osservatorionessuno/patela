/*
* This file is heavily inspired/copied from https://github.com/parallaxsecond/rust-tss-esapi
 */

use tss_esapi::constants::{CapabilityType, tss::TPM2_PERSISTENT_FIRST};
use tss_esapi::handles::{ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Provision;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    CapabilityData, CreatePrimaryKeyResult, Data, HashScheme, PublicKeyRsa, RsaDecryptionScheme,
    RsaExponent,
};
use tss_esapi::tss2_esys::TPM2_HANDLE;
use tss_esapi::utils::create_unrestricted_encryption_decryption_rsa_public;
use tss_esapi::{
    Context,
    handles::KeyHandle,
    interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
};

use std::convert::{TryFrom, TryInto};

pub const IV: [u8; 16] = [
    188, 144, 53, 87, 189, 188, 155, 229, 226, 213, 117, 121, 51, 244, 175, 89,
];

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
        if let CapabilityData::Handles(persistent_handles) = capability_data {
            if let Some(&retrieved_persistent_handle) = persistent_handles.first() {
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
            //let rsa_pub_key = ctx
            //    .load_external_public(encrypt_key.out_public.clone(), Hierarchy::Null)
            //    .unwrap();
            //
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
