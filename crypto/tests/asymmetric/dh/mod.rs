use crypto::asymmetric::dh::{DHParameters, RFC2409_PRIME_768, RFC2409_GENERATOR_768,
        RFC2409_PRIME_1024, RFC2409_GENERATOR_1024};


fn test_exhange_with_params(params: &DHParameters) {
    let priv_key1 = params.private_key();
    let priv_key2 = params.private_key();
    let pub_key1 = priv_key1.public_key();
    let pub_key2 = priv_key2.public_key();
    let shared_key1 = priv_key2.exchange(&pub_key1);
    let shared_key2 = priv_key1.exchange(&pub_key2);
    assert!(shared_key1 == shared_key2);
}

#[test]
fn test_exchange() {
    test_exhange_with_params(&DHParameters::new(&[0x17], 5));
    test_exhange_with_params(&DHParameters::new(&RFC2409_PRIME_768, RFC2409_GENERATOR_768));
    test_exhange_with_params(&DHParameters::new(&RFC2409_PRIME_1024, RFC2409_GENERATOR_1024));
}
