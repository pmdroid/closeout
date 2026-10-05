use pgp::composed::{
    ArmorOptions, Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::Password;
use rand::rngs::OsRng;
use smallvec::smallvec;

pub fn generate_pgp_keys() -> Result<(String, String), String> {
    let mut rng = OsRng;
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Closeout <closeout@localhost>".into())
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES128])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha256])
        .preferred_compression_algorithms(smallvec![])
        .subkeys(vec![SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_encrypt(EncryptionCaps::All)
            .build()
            .map_err(|err| err.to_string())?]);
    let secret = key_params.build().map_err(|err| err.to_string())?.generate(&mut rng).map_err(|err| err.to_string())?;
    let public = secret.to_public_key();
    let public_armor = public.to_armored_string(ArmorOptions::default()).map_err(|err| err.to_string())?;
    let private_armor = secret.to_armored_string(ArmorOptions::default()).map_err(|err| err.to_string())?;
    Ok((public_armor, private_armor))
}

pub fn seal_report(public_key_armor: &str, plaintext: &str) -> Result<String, String> {
    let (public_key, _) = SignedPublicKey::from_string(public_key_armor).map_err(|_| "public key is invalid".to_string())?;
    let subkey = public_key.public_subkeys.first().ok_or("public key cannot seal a report")?;
    let mut rng = OsRng;
    let mut builder = MessageBuilder::from_bytes("closeout.md", plaintext.as_bytes().to_vec()).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES128);
    builder.encrypt_to_key(&mut rng, subkey).map_err(|_| "public key cannot seal a report".to_string())?;
    builder.to_armored_string(&mut rng, ArmorOptions::default()).map_err(|_| "public key cannot seal a report".to_string())
}

pub fn open_report(private_key_armor: &str, armor: &str) -> Result<String, String> {
    let (secret, _) = SignedSecretKey::from_string(private_key_armor).map_err(|_| "private key is invalid".to_string())?;
    let (message, _) = Message::from_string(armor).map_err(|_| "sealed report cannot be decrypted".to_string())?;
    let mut decrypted = message.decrypt(&Password::empty(), &secret).map_err(|_| "sealed report cannot be decrypted".to_string())?;
    decrypted.as_data_string().map_err(|_| "sealed report cannot be decrypted".to_string())
}
