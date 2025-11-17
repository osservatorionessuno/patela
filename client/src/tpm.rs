use tss_esapi::abstraction::{AsymmetricAlgorithmSelection, ak, ek};
use tss_esapi::attributes::{NvIndexAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::CapabilityType;
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{AuthHandle, NvIndexHandle, NvIndexTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::reserved_handles::{NvAuth, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    CapabilityData, Digest, EncryptedSecret, IdObject, MaxNvBuffer, NvPublicBuilder, Public,
    SymmetricDefinition,
};
use tss_esapi::tss2_esys::TPM2_HANDLE;
use tss_esapi::{Context, handles::KeyHandle};

use anyhow::Context as AnyhowContext;
use std::convert::TryFrom;
use tss_esapi::traits::Marshall;

pub fn load_attestation_keys(
    context: &mut Context,
) -> anyhow::Result<(KeyHandle, Public, KeyHandle, Public)> {
    let ek_ecc = ek::create_ek_object(
        context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        None,
    )
    .context("Failed to create EK ECC object")?;

    let (ek_pub, _, _) = context
        .read_public(ek_ecc)
        .context("Failed to read EK public key")?;

    let ak_res = ak::create_ak(
        context,
        ek_ecc,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        SignatureSchemeAlgorithm::EcDsa,
        None,
        None,
    )
    .context("Failed to create AK")?;

    let ak_ecc = ak::load_ak(context, ek_ecc, None, ak_res.out_private, ak_res.out_public)
        .context("Failed to load AK")?;

    let (ak_pub, _, _) = context
        .read_public(ak_ecc)
        .context("Failed to read AK public key")?;

    Ok((ek_ecc, ek_pub, ak_ecc, ak_pub))
}

pub fn resolve_attestation_challenge(
    context: &mut Context,
    ek_ecc: KeyHandle,
    ak_ecc: KeyHandle,
    credential_blob: IdObject,
    encrypted_secret: EncryptedSecret,
) -> anyhow::Result<Digest> {
    let (session_1, session_2) = load_attestation_sessions(context)?;

    context.set_sessions((Some(session_1), Some(session_2), None));
    let decrypted = context
        .activate_credential(ak_ecc, ek_ecc, credential_blob, encrypted_secret)
        .context("Failed to activate credential")?;

    context
        .flush_context(ek_ecc.into())
        .context("Failed to flush EK context")?;
    context
        .flush_context(ak_ecc.into())
        .context("Failed to flush AK context")?;

    Ok(decrypted)
}

pub fn load_attestation_sessions(
    context: &mut Context,
) -> anyhow::Result<(AuthSession, AuthSession)> {
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

    let session_1 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("Failed to call start_auth_session for HMAC session")?
        .ok_or_else(|| anyhow::anyhow!("Invalid HMAC session value returned"))?;

    context
        .tr_sess_set_attributes(session_1, session_attributes, session_attributes_mask)
        .context("Failed to set attributes for HMAC session")?;

    let session_2 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("Failed to call start_auth_session for Policy session")?
        .ok_or_else(|| anyhow::anyhow!("Invalid Policy session value returned"))?;

    context
        .tr_sess_set_attributes(session_2, session_attributes, session_attributes_mask)
        .context("Failed to call tr_sess_set_attributes for Policy session")?;

    context
        .execute_with_session(Some(session_1), |ctx| {
            let policy_session = PolicySession::try_from(session_2)?;
            ctx.policy_secret(
                policy_session,
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .context("Failed to execute policy secret (or convert auth session to policy session)")?;

    Ok((session_1, session_2))
}

pub fn public_key_to_hex(public: &Public) -> anyhow::Result<String> {
    let bytes = public.marshall()?;
    Ok(hex::encode(bytes))
}

const NV_INDEX: u32 = 0x01000000; // Start of owner range
const MAX_CHUNK_SIZE: usize = 512;
const TPM2_PT_NV_INDEX_MAX: u32 = 0x00000117;

pub fn get_max_nv_size(ctx: &mut Context) -> anyhow::Result<usize> {
    let (capability_data, _) = ctx
        .get_capability(CapabilityType::TpmProperties, TPM2_PT_NV_INDEX_MAX, 1)
        .context("Failed to query TPM2_PT_NV_INDEX_MAX")?;

    if let CapabilityData::TpmProperties(props) = capability_data
        && let Some(prop) = props.first()
    {
        return Ok(prop.value() as usize);
    }

    anyhow::bail!("Failed to get max NV index size from TPM")
}

pub fn get_nv_index_handle(ctx: &mut Context) -> anyhow::Result<(NvIndexHandle, usize)> {
    let max_size = get_max_nv_size(ctx)?;
    let nv_index_tpm_handle = NvIndexTpmHandle::new(NV_INDEX)?;

    if nv_index_exists(ctx, NV_INDEX)? {
        let handle = ctx
            .tr_from_tpm_public(TpmHandle::NvIndex(nv_index_tpm_handle))
            .context("Failed to get existing NV index handle")?;

        let nv_public = ctx
            .nv_read_public(handle.into())
            .context("Failed to read NV public area")?;

        let existing_size = nv_public.0.data_size();

        if existing_size != max_size {
            eprintln!(
                "Warning: Existing NV index has size {}, but TPM max is {}. Consider recreating.",
                existing_size, max_size
            );
        }

        Ok((handle.into(), existing_size))
    } else {
        let handle = create_nv_index(ctx, nv_index_tpm_handle, max_size)?;
        Ok((handle, max_size))
    }
}

fn nv_index_exists(ctx: &mut Context, index: u32) -> anyhow::Result<bool> {
    let mut property = 0x01000000u32;

    loop {
        let (capability_data, more) = ctx
            .get_capability(CapabilityType::Handles, property, 100)
            .context("Failed to query NV indices")?;

        if let CapabilityData::Handles(handles) = capability_data {
            if handles.iter().any(|&h| TPM2_HANDLE::from(h) == index) {
                return Ok(true);
            }
            if let Some(&last) = handles.last() {
                property = TPM2_HANDLE::from(last) + 1;
            }
        }

        if !more {
            break;
        }
    }

    Ok(false)
}

fn create_nv_index(
    ctx: &mut Context,
    nv_index_tpm_handle: NvIndexTpmHandle,
    size: usize,
) -> anyhow::Result<NvIndexHandle> {
    let attrs = NvIndexAttributesBuilder::new()
        .with_owner_read(true)
        .with_owner_write(true)
        .with_read_stclear(true)
        .build()?;

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index_tpm_handle)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attrs)
        .with_data_area_size(size)
        .build()?;

    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or_else(|| anyhow::anyhow!("Failed to create auth session"))?;

    ctx.execute_with_session(Some(session), |ctx| {
        ctx.nv_define_space(Provision::Owner, None, nv_public)
    })
    .context("Failed to define NV space")?;

    ctx.flush_context(SessionHandle::from(session).into())
        .with_context(|| "Failed to clear session")?;

    ctx.tr_from_tpm_public(TpmHandle::NvIndex(nv_index_tpm_handle))
        .map(Into::into)
        .context("Failed to get newly created NV index handle")
}

pub fn nv_write_data(
    ctx: &mut Context,
    nv_handle: NvIndexHandle,
    data: &[u8],
) -> anyhow::Result<()> {
    let mut offset = 0usize;

    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or_else(|| anyhow::anyhow!("Failed to create auth session"))?;

    for chunk in data.chunks(MAX_CHUNK_SIZE) {
        let buffer = MaxNvBuffer::try_from(chunk.to_vec()).context("Failed to create NV buffer")?;

        ctx.execute_with_session(Some(session), |ctx| {
            ctx.nv_write(NvAuth::Owner, nv_handle, buffer, offset as u16)
        })
        .with_context(|| format!("Failed to write chunk at offset {}", offset))?;

        offset += chunk.len();
    }

    ctx.flush_context(SessionHandle::from(session).into())
        .with_context(|| "Failed to clear session")?;

    Ok(())
}

pub fn nv_read_data(ctx: &mut Context, nv_handle: NvIndexHandle) -> anyhow::Result<Vec<u8>> {
    let nv_public = ctx
        .nv_read_public(nv_handle)
        .context("Failed to read NV public area")?;

    let size = nv_public.0.data_size();
    let mut result = vec![0u8; size];
    let mut offset = 0usize;

    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or_else(|| anyhow::anyhow!("Failed to create auth session"))?;

    for chunk in result.chunks_mut(MAX_CHUNK_SIZE) {
        let chunk_size = chunk.len() as u16;

        let data = ctx
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.nv_read(NvAuth::Owner, nv_handle, chunk_size, offset as u16)
            })
            .with_context(|| format!("Failed to read chunk at offset {}", offset))?;

        let vec = data.to_vec();
        anyhow::ensure!(
            vec.len() == chunk.len(),
            "Expected {} bytes at offset {}, got {}",
            chunk.len(),
            offset,
            vec.len()
        );

        chunk.copy_from_slice(&vec);
        offset += chunk.len();
    }

    ctx.flush_context(SessionHandle::from(session).into())
        .with_context(|| "Failed to clear session")?;

    Ok(result)
}

pub fn delete_nv_index(ctx: &mut Context, nv_handle: NvIndexHandle) -> anyhow::Result<()> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or_else(|| anyhow::anyhow!("Failed to create auth session"))?;

    ctx.execute_with_session(Some(session), |ctx| {
        ctx.nv_undefine_space(Provision::Owner, nv_handle)
    })
    .context("Failed to delete NV index")?;

    ctx.flush_context(SessionHandle::from(session).into())
        .with_context(|| "Failed to clear session")?;

    Ok(())
}
