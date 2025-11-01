use elliptic_curve::PublicKey;
use tss_esapi::structures::{EncryptedSecret, IdObject, Name, Public};
use tss_esapi::utils::make_credential_ecc;

pub fn create_attestation_credentials(
    ek_public: Public,
    ak_name: Name,
    challange: &[u8],
) -> anyhow::Result<(IdObject, EncryptedSecret)> {
    // This can be done without tpm
    let (credential_blob, encrypted_secret) = make_credential_ecc::<_, sha2::Sha256, aes::Aes128>(
        PublicKey::<p256::NistP256>::try_from(&ek_public)?,
        challange,
        ak_name,
    )?;

    Ok((credential_blob, encrypted_secret))
}
