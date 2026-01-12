use super::{sha512, sha384};

/// This calls the typescript SHA512 implementation
#[oracle(getSHA512)]
unconstrained fn get_sha512_hash<let N: u32>(input: BoundedVec<u8, N>) -> [u8; 64] {
}

/// This calls the typescript SHA384 implementation
#[oracle(getSHA384)]
unconstrained fn get_sha384_hash<let N: u32>(input: BoundedVec<u8, N>) -> [u8; 48] {
}

/// sanitizes a BoundedVec by constraining its length since the fuzzer can generate invalid lengths
unconstrained fn sanitize_bounded_vec<let N: u32>(input: BoundedVec<u8, N>) -> BoundedVec<u8, N> {
    let sanitized_len = input.len() % (N + 1);

    // Create a new BoundedVec with the sanitized length
    let mut new_input = BoundedVec::<u8, N>::new();
    for i in 0..sanitized_len {
        new_input.push(input.storage()[i]);
    }

    new_input
}

#[test]
unconstrained fn test_sha512_1(input: BoundedVec<u8, 1>) {
    let sanitized_input = sanitize_bounded_vec(input);

    let noir_hash = sha512::sha512_var(sanitized_input);

    let ts_hash = get_sha512_hash(input);

    assert_eq(noir_hash, ts_hash);
}

#[test]
unconstrained fn test_sha512_100(input: BoundedVec<u8, 100>) {
    let sanitized_input = sanitize_bounded_vec(input);

    let noir_hash = sha512::sha512_var(sanitized_input);

    let ts_hash = get_sha512_hash(input);

    assert_eq(noir_hash, ts_hash);
}

#[test]
unconstrained fn test_sha512_256(input: BoundedVec<u8, 256>) {
    let sanitized_input = sanitize_bounded_vec(input);

    let noir_hash = sha512::sha512_var(sanitized_input);

    let ts_hash = get_sha512_hash(input);

    assert_eq(noir_hash, ts_hash);
}

// SHA384 Tests

#[test]
unconstrained fn test_sha384_1(input: BoundedVec<u8, 1>) {
    let sanitized_input = sanitize_bounded_vec(input);

    let noir_hash = sha384::sha384_var(sanitized_input);

    let ts_hash = get_sha384_hash(input);

    assert_eq(noir_hash, ts_hash);
}

#[test]
unconstrained fn test_sha384_100(input: BoundedVec<u8, 100>) {
    let sanitized_input = sanitize_bounded_vec(input);

    let noir_hash = sha384::sha384_var(sanitized_input);

    let ts_hash = get_sha384_hash(input);

    assert_eq(noir_hash, ts_hash);
}

#[test]
unconstrained fn test_sha384_256(input: BoundedVec<u8, 256>) {
    let sanitized_input = sanitize_bounded_vec(input);

    let noir_hash = sha384::sha384_var(sanitized_input);

    let ts_hash = get_sha384_hash(input);

    assert_eq(noir_hash, ts_hash);
}
