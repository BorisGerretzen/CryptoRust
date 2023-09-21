use rabe_bn::{Group, Gt, G1, G2};
use rand::Rng;

use abe::crypto::{adapt, decrypt, encrypt, keygen, setup};
use abe::parser::AccessTreeParser;

#[test]
fn test_adapt_eq() {
    let rng = &mut rand::thread_rng();
    let attributes = vec!["A".to_string(), "B".to_string()];
    let (public_key, master_key) = setup(&attributes, G1::one(), G2::one(), rng);
    let (adapted_public, adapted_master) =
        adapt(&public_key, &master_key, &vec!["C".to_string()], rng);

    // PUBLIC
    // Basic eq
    assert_eq!(adapted_public.g1, public_key.g1);
    assert_eq!(adapted_public.g2, public_key.g2);
    assert_eq!(adapted_public.y, public_key.y);
    assert_eq!(adapted_public.map, public_key.map);

    // Check that the values in the original big_t are in the adapted big_t
    for (key, value) in public_key.big_t.iter() {
        assert_eq!(adapted_public.big_t[key], *value);
    }

    // Check that C is not in the original big_t
    assert_eq!(public_key.big_t.contains_key("C"), false);
    assert_eq!(adapted_public.big_t.contains_key("C"), true);

    // MASTER
    assert_eq!(adapted_master.alpha, master_key.alpha);

    // Check that the values in the original small_t are in the adapted small_t
    for (key, value) in master_key.small_t.iter() {
        assert_eq!(adapted_master.small_t[key], *value);
    }
}

#[test]
fn test_original_secret_decrypts_adapted_pk() {
    let mut parser = AccessTreeParser::new("(A&B)");
    let tree = parser.parse().unwrap();

    let rng = &mut rand::thread_rng();
    let secret: Gt = rng.gen();

    let message_bytes = String::from("Hello World!").into_bytes();

    let attributes = vec!["A".to_string(), "B".to_string()];

    let (public_key, master_key) = setup(&attributes, G1::one(), G2::one(), rng);

    let secret_key = keygen(
        &vec!["A".to_string(), "B".to_string()],
        &public_key,
        &master_key,
        rng,
    )
    .unwrap();

    let (adapted_public, adapted_master) =
        adapt(&public_key, &master_key, &vec!["C".to_string()], rng);

    let cipher_text = encrypt(&secret, &message_bytes, &adapted_public, &tree, rng).unwrap();
    let decrypted = decrypt(&cipher_text, &secret_key).unwrap();

    assert_eq!(secret, decrypted.secret);
    assert_eq!(message_bytes, decrypted.message);
}

#[test]
fn test_new_key_decrypts_old_data() {
    let mut parser = AccessTreeParser::new("(A&B)");
    let tree = parser.parse().unwrap();

    let rng = &mut rand::thread_rng();
    let secret: Gt = rng.gen();

    let message_bytes = String::from("Hello World!").into_bytes();

    let attributes = vec!["A".to_string(), "B".to_string()];

    let (public_key, master_key) = setup(&attributes, G1::one(), G2::one(), rng);

    let (adapted_public, adapted_master) =
        adapt(&public_key, &master_key, &vec!["C".to_string()], rng);

    let new_secret = keygen(
        &vec!["A".to_string(), "B".to_string(), "C".to_string()],
        &adapted_public,
        &adapted_master,
        rng,
    )
    .unwrap();

    let cipher_text = encrypt(&secret, &message_bytes, &public_key, &tree, rng).unwrap();
    let decrypted = decrypt(&cipher_text, &new_secret).unwrap();

    assert_eq!(secret, decrypted.secret);
    assert_eq!(message_bytes, decrypted.message);
}
