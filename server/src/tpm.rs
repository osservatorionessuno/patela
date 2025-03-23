use tss_esapi::{
    Context, TctiNameConf,
    interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
    structures::{Attest, EncryptedSecret, IdObject, MaxBuffer, Public, Signature, VerifiedTicket},
    traits::Marshall,
};

pub struct PatelaTpmContext {
    ctx: Context,
}

impl PatelaTpmContext {
    pub fn new() -> anyhow::Result<Self> {
        // TODO: map errors
        //.expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
        //.expect("Failed to create Context");

        Ok(Self {
            ctx: Context::new(TctiNameConf::from_environment_variable()?)?,
        })
    }

    pub fn client_challange_create(
        mut self,
        ak_public: Public,
        ek_public: Public,
    ) -> anyhow::Result<(IdObject, EncryptedSecret)> {
        // ================================================================================
        // At this point we have what we need: The EK X509 DER, EK Public and AIK public for the
        // certifying authority. They are in the corresponding variables right now.

        // ek_pubcert
        // ek_public
        // ak_public

        // Here, the authority should validate that the EK X509 DER is from a trusted authority,
        // the the EK public key matches the public key from EK X509 DER.

        // The authority should also validate the AIK has valid properties such as fixedParent
        // and fixedTPM so that we can assert the AIK is bound to this single device, and that
        // this is a restricted key which does not allow signature of external inputs.

        // In our example, we will be taking the trust approach known as "yolo" by verifying none
        // of these details. This is considered unwise in production. Do not be like me.

        // Load the AIK public, and derive it's "name". This will be used as part of the
        // challenge encryption.
        let (_public, ak_name, _qualified_name) = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                let ak_handle = ctx.load_external_public(ak_public.clone(), Hierarchy::Null)?;
                let r = ctx.read_public(ak_handle);
                ctx.flush_context(ak_handle.into())?;
                r
            })
            .expect("Unable to read AIK public");

        let ak_public_object_attributes = ak_public.object_attributes();
        assert!(ak_public_object_attributes.fixed_tpm());
        assert!(ak_public_object_attributes.fixed_parent());
        assert!(ak_public_object_attributes.restricted());

        // We now create our challenge that we will encrypt. We use 16 bytes (128bit) for
        // a sufficiently random value.
        //
        // Importantly, the authority MUST persist this value for verification in a future
        // step. This value MUST NOT be disclosed!
        let challenge = self
            .ctx
            .get_random(16)
            .expect("Unable to access random data.");

        // Now we load the ek_public, and create our encrypted challenge.
        let (idobject, encrypted_secret) = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                let ek_handle = ctx.load_external_public(ek_public, Hierarchy::Null)?;
                let r = ctx.make_credential(ek_handle, challenge.clone(), ak_name);
                ctx.flush_context(ek_handle.into())?;
                r
            })
            .expect("Unable to create encrypted challenge");

        Ok((idobject, encrypted_secret))
    }

    pub fn client_challange_validate(
        mut self,
        ak_public: Public,
        signature: Signature,
        attest: Attest,
    ) -> anyhow::Result<VerifiedTicket> {
        // Now back on our certifying authority, we want to assert that the attestation we
        // received really did come from this TPM. We can use the AIK to demonstrate this
        // linkage, to trust that the object must come from a valid TPM that we trust to
        // behave in a certain manner.
        //
        // Depending on your use case, you may need to validate other properties around
        // the attestation signature.

        // First, load the public from the aik
        let ak_handle = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.load_external_public(
                    ak_public,
                    // We put it into the null hierarchy as this is ephemeral.
                    Hierarchy::Null,
                )
            })
            .expect("Failed to load aik public");

        let attest_data: MaxBuffer = attest
            .marshall()
            .expect("Unable to marshall")
            .try_into()
            .expect("Data too large");

        let hash_alg = HashingAlgorithm::Sha256;

        let (attest_digest, _ticket) = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                // Important to note that this MUST match the ak hash algorithm
                ctx.hash(attest_data, hash_alg, Hierarchy::Null)
            })
            .expect("Failed to digest attestation output");

        let verified_ticket = self
            .ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.verify_signature(ak_handle, attest_digest, signature)
            })
            .expect("Failed to verify attestation");

        println!("verification: {:?}", verified_ticket);

        Ok(verified_ticket)
    }
}
