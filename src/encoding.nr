use crate::tables::{
    BASE4_ENCODE_1BIT_TABLE, BASE4_ENCODE_3BIT_TABLE, BASE4_ENCODE_4BIT_TABLE,
    BASE4_ENCODE_5BIT_TABLE, BASE4_ENCODE_6BIT_TABLE, BASE4_ENCODE_7BIT_TABLE,
    BASE4_ENCODE_8BIT_TABLE, BASE4_ENCODE_9BIT_TABLE, BASE4_MAJORITY_DECODE_5BIT_TABLE,
    BASE4_PARTIAL_CHOOSE_DECODE_5BIT_TABLE, BASE4_POWERS, BASE4_XOR_DECODE_5BIT_TABLE,
};

unconstrained fn decompose_e(e: Field) -> [Field; 9] {
    let mut r: [Field; 9] = [0; 9];
    let mut bytes = e.to_le_bytes::<8>();
    let b8to14 = bytes[1] & 63;
    let b14to16 = bytes[1] >> 6;
    let b16to18 = bytes[2] & 3;
    let b18to24 = bytes[2] >> 2;
    let b40to41 = bytes[5] & 1;
    let b41to48 = bytes[5] >> 1;

    r[0] = bytes[0] as Field; // 0-8
    r[1] = b8to14 as Field; // 8-14
    r[2] = (b14to16 + (b16to18 << 2)) as Field; // 14-18
    r[3] = b18to24 as Field;
    r[4] = bytes[3] as Field;
    r[5] = bytes[4] as Field + (b40to41 as Field) * 256;
    r[6] = b41to48 as Field;
    r[7] = bytes[6] as Field;
    r[8] = bytes[7] as Field;
    r
}

unconstrained fn decompose_a(a: Field) -> [Field; 9] {
    let mut r: [Field; 9] = [0; 9];
    let mut bytes = a.to_le_bytes::<8>();
    let b24to28 = bytes[3] & 15;
    let b28to32 = bytes[3] >> 4;
    let b32to34 = bytes[4] & 3;
    let b34to39 = (bytes[4] >> 2) & 31;
    let b39to40 = bytes[4] >> 7;
    r[0] = bytes[0] as Field;
    r[1] = bytes[1] as Field;
    r[2] = bytes[2] as Field;
    r[3] = b24to28 as Field;
    r[4] = (b28to32 + (b32to34 << 4)) as Field;
    r[5] = b34to39 as Field;
    r[6] = b39to40 as Field + (bytes[5] as Field * 2);
    r[7] = bytes[6] as Field;
    r[8] = bytes[7] as Field;
    r
    /*
    let mut a64 = a as u64;

    r[0] = (a64 & 127) as Field;
    a64 >>= 7;
    r[1] = (a64 & 127) as Field;
    a64 >>= 7;
    r[2] = (a64 & 127) as Field;
    a64 >>= 7;
    r[3] = (a64 & 127) as Field;
    a64 >>= 7;
    r[4] = (a64 & 63) as Field;
    a64 >>= 6;
    r[5] = (a64 & 31) as Field;
    a64 >>= 5;
    r[6] = (a64 & 255) as Field;
    a64 >>= 8;
    r[7] = (a64 & 255) as Field;
    a64 >>= 8;
    r[8] = (a64 & 511) as Field;
    // 1000000
    */

}

pub(crate) struct EncodedMajority {
    pub(crate) raw: Field,
    pub(crate) a: Field,
    pub(crate) ror28: Field,
    pub(crate) ror34: Field,
    pub(crate) ror39: Field,
}

pub(crate) struct EncodedChoose {
    pub(crate) raw: Field,
    pub(crate) e: Field,
    pub(crate) ror14: Field,
    pub(crate) ror18: Field,
    pub(crate) ror41: Field,
}

pub(crate) struct EncodedWitness {
    pub(crate) raw: Field,
    pub(crate) w: Field,
    pub(crate) ror1: Field,
    pub(crate) ror8: Field,
    pub(crate) ror19: Field,
    pub(crate) ror61: Field,
    pub(crate) rshift6: Field,
    pub(crate) rshift7: Field,
}

impl EncodedWitness {
    pub(crate) fn new() -> Self {
        EncodedWitness {
            raw: 0,
            w: 0,
            ror1: 0,
            ror8: 0,
            ror19: 0,
            ror61: 0,
            rshift6: 0,
            rshift7: 0,
        }
    }
}

unconstrained fn __decompose_witness(w: Field) -> [Field; 12] {
    //   1, 5, 1, 1, 8, 3, 8, 8, 8, 9, 9, 3
    let mut acc: u64 = w as u64;
    let mut r: [Field; 12] = [0; 12];

    r[0] = (acc & 1) as Field;
    acc >>= 1;
    r[1] = (acc & 31) as Field;
    acc >>= 5;
    r[2] = (acc & 1) as Field;
    acc >>= 1;
    r[3] = (acc & 1) as Field;
    acc >>= 1;
    r[4] = (acc & 255) as Field;
    acc >>= 8;
    r[5] = (acc & 7) as Field;
    acc >>= 3;
    r[6] = (acc & 255) as Field;
    acc >>= 8;
    r[7] = (acc & 255) as Field;
    acc >>= 8;
    r[8] = (acc & 255) as Field;
    acc >>= 8;
    r[9] = (acc & 511) as Field;
    acc >>= 9;
    r[10] = (acc & 511) as Field;
    acc >>= 9;
    r[11] = (acc & 7) as Field;
    r
}

// unconstrained fn __decompose_w15(w15: Field) -> [Field; 10] {
//     let mut r: [Field; 10] = [0; 10];
//     let mut bytes = w15.to_le_bytes::<8>();
//     let b1 = bytes[0] & 1;
//     let b1tob7 = (bytes[0] >> 1) & 63;
//     let b8 = bytes[0] >> 7;

//     r[0] = b1 as Field;
//     r[1] = b1tob7 as Field;
//     r[2] = b8 as Field;
//     r[3] = bytes[1] as Field;
//     r[4] = bytes[2] as Field;
//     r[5] = bytes[3] as Field;
//     r[6] = bytes[4] as Field;
//     r[7] = bytes[5] as Field;
//     r[8] = bytes[6] as Field;
//     r[9] = bytes[7] as Field;
//     r
// }

// unconstrained fn __decompose_w2(w2: Field) -> [Field; 9] {
//     let mut acc: u64 = w2 as u64;
//     let mut r: [Field; 9] = [0; 9];

//     r[0] = (acc & 63) as Field;
//     acc >>= 6;
//     r[1] = (acc & 255) as Field;
//     acc >>= 8;
//     r[2] = (acc & 31) as Field;
//     acc >>= 5;
//     r[3] = (acc & 255) as Field;
//     acc >>= 8;
//     r[4] = (acc & 255) as Field;
//     acc >>= 8;
//     r[5] = (acc & 255) as Field;
//     acc >>= 8;
//     r[6] = (acc & 511) as Field;
//     acc >>= 9;
//     r[7] = (acc & 511) as Field;
//     acc >>= 9;
//     r[8] = (acc & 7) as Field;
//     r
// }

// fn encode_second_message_extension(w2: Field) -> EncodedS1 {
//     //Safety: split input into slices with the following bit sizes:
//     //        6,8,5,8,8,8,9,9,3
//     //        We need to validate the correctness of these slice claims by asserting their sum equals `w15`,
//     //        and we also need to validate the bit range of each slice
//     //        (we get an implicit range constraint for free by indexing our BASE4_ENCODE_TABLE lookup tables)

//     // 19, 61, 6
//     let s = unsafe { __decompose_w2(w2) };

//     let mut reconstructed = s[8];
//     reconstructed *= 512;
//     reconstructed += s[7];
//     reconstructed *= 512;
//     reconstructed += s[6];
//     reconstructed *= 256;
//     reconstructed += s[5];
//     reconstructed *= 256;
//     reconstructed += s[4];
//     reconstructed *= 256;
//     reconstructed += s[3];
//     reconstructed *= 32;
//     reconstructed += s[2];
//     reconstructed *= 256;
//     reconstructed += s[1];
//     reconstructed *= 64;
//     reconstructed += s[0];
//     assert_eq(reconstructed, w2); // 7 gates?

//     let mut base4_encoded_slices: [Field; 9] = [0; 9];
//     // 18 gates?
//     base4_encoded_slices[0] = BASE4_ENCODE_6BIT_TABLE[s[0]];
//     base4_encoded_slices[1] = BASE4_ENCODE_8BIT_TABLE[s[1]];
//     base4_encoded_slices[2] = BASE4_ENCODE_5BIT_TABLE[s[2]];
//     base4_encoded_slices[3] = BASE4_ENCODE_8BIT_TABLE[s[3]];
//     base4_encoded_slices[4] = BASE4_ENCODE_8BIT_TABLE[s[4]];
//     base4_encoded_slices[5] = BASE4_ENCODE_8BIT_TABLE[s[5]];
//     base4_encoded_slices[6] = BASE4_ENCODE_9BIT_TABLE[s[6]];
//     base4_encoded_slices[7] = BASE4_ENCODE_9BIT_TABLE[s[7]];
//     base4_encoded_slices[8] = BASE4_ENCODE_3BIT_TABLE[s[8]];

//     let high3 = base4_encoded_slices[8];

//     let mut high45 = base4_encoded_slices[7];
//     high45 *= BASE4_POWERS[9];
//     high45 += base4_encoded_slices[6];
//     high45 *= BASE4_POWERS[8];
//     high45 += base4_encoded_slices[5];
//     high45 *= BASE4_POWERS[8];
//     high45 += base4_encoded_slices[4];
//     high45 *= BASE4_POWERS[8];
//     high45 += base4_encoded_slices[3];

//     let mut high58 = high45 * BASE4_POWERS[5];
//     high58 += base4_encoded_slices[2];
//     high58 *= BASE4_POWERS[8];
//     high58 += base4_encoded_slices[1];

//     let low61: Field = high58 * BASE4_POWERS[6] + base4_encoded_slices[0];

//     high45 += base4_encoded_slices[8] * BASE4_POWERS[42];
//     high58 += base4_encoded_slices[8] * BASE4_POWERS[55];

//     let mut low19 = base4_encoded_slices[0]
//         + base4_encoded_slices[1] * BASE4_POWERS[6]
//         + base4_encoded_slices[2] * BASE4_POWERS[14];

//     let w_ror19 = low19 * BASE4_POWERS[45] + high45;
//     let w_ror61 = low61 * BASE4_POWERS[3] + high3;
//     let w_rshift6 = high58;
//     let w_ror0 = low19 + high45 * BASE4_POWERS[19];

//     EncodedS1 { raw: w2, w: w_ror0, w_ror19, w_ror61, w_rshift6 }
// }

pub(crate) fn encode_message_extension(w: Field) -> EncodedWitness {
    //Safety: split input into slices with the following bit sizes:
    //   1, 5, 1, 1, 8, 3, 8, 8, 8, 9, 9, 3
    //        We need to validate the correctness of these slice claims by asserting their sum equals `w`,
    //        and we also need to validate the bit range of each slice
    //        (we get an implicit range constraint for free by indexing our BASE4_ENCODE_TABLE lookup tables)
    let s: [Field; 12] = unsafe { __decompose_witness(w) };

    let mut reconstructed = s[11];
    reconstructed *= 512;
    reconstructed += s[10];
    reconstructed *= 512;
    reconstructed += s[9];
    reconstructed *= 256;
    reconstructed += s[8];
    reconstructed *= 256;
    reconstructed += s[7];
    reconstructed *= 256;
    reconstructed += s[6];
    reconstructed *= 8;
    reconstructed += s[5];
    reconstructed *= 256;
    reconstructed += s[4];
    reconstructed *= 2;
    reconstructed += s[3];
    reconstructed *= 2;
    reconstructed += s[2];
    reconstructed *= 32;
    reconstructed += s[1];
    reconstructed *= 2;
    reconstructed += s[0];
    assert_eq(reconstructed, w);

    let mut base4_encoded_slices: [Field; 12] = [0; 12];
    //   1, 5, 1, 1, 8, 3, 8, 8, 8, 9, 9, 3

    base4_encoded_slices[0] = BASE4_ENCODE_1BIT_TABLE[s[0]];
    base4_encoded_slices[1] = BASE4_ENCODE_5BIT_TABLE[s[1]];
    base4_encoded_slices[2] = BASE4_ENCODE_1BIT_TABLE[s[2]];
    base4_encoded_slices[3] = BASE4_ENCODE_1BIT_TABLE[s[3]];
    base4_encoded_slices[4] = BASE4_ENCODE_8BIT_TABLE[s[4]];
    base4_encoded_slices[5] = BASE4_ENCODE_3BIT_TABLE[s[5]];
    base4_encoded_slices[6] = BASE4_ENCODE_8BIT_TABLE[s[6]];
    base4_encoded_slices[7] = BASE4_ENCODE_8BIT_TABLE[s[7]];
    base4_encoded_slices[8] = BASE4_ENCODE_8BIT_TABLE[s[8]];
    base4_encoded_slices[9] = BASE4_ENCODE_9BIT_TABLE[s[9]];
    base4_encoded_slices[10] = BASE4_ENCODE_9BIT_TABLE[s[10]];
    base4_encoded_slices[11] = BASE4_ENCODE_3BIT_TABLE[s[11]];

    // 42
    let mut bits19to61 = base4_encoded_slices[10];
    bits19to61 *= BASE4_POWERS[9];
    bits19to61 += base4_encoded_slices[9];
    bits19to61 *= BASE4_POWERS[8];
    bits19to61 += base4_encoded_slices[8];
    bits19to61 *= BASE4_POWERS[8];
    bits19to61 += base4_encoded_slices[7];
    bits19to61 *= BASE4_POWERS[8];
    bits19to61 += base4_encoded_slices[6];

    let mut bits8to61 = bits19to61 * BASE4_POWERS[3];
    bits8to61 += base4_encoded_slices[5];
    bits8to61 *= BASE4_POWERS[8];
    bits8to61 += base4_encoded_slices[4];

    let low1 = base4_encoded_slices[0];

    let bits1to8 = base4_encoded_slices[1]
        + base4_encoded_slices[2] * BASE4_POWERS[5]
        + base4_encoded_slices[3] * BASE4_POWERS[6];

    let low8 = low1 + bits1to8 * BASE4_POWERS[1];

    let low61 = bits8to61 * BASE4_POWERS[8] + low8;

    let low19 = low8
        + base4_encoded_slices[4] * BASE4_POWERS[8]
        + base4_encoded_slices[5] * BASE4_POWERS[16];

    let high3 = base4_encoded_slices[11];

    let high45 = bits19to61 + base4_encoded_slices[11] * BASE4_POWERS[42];

    let high56 = bits8to61 + base4_encoded_slices[11] * BASE4_POWERS[53];

    let high57 = high56 * BASE4_POWERS[1] + base4_encoded_slices[3];
    let high58 = high57 * BASE4_POWERS[1] + base4_encoded_slices[2];

    let high63 = base4_encoded_slices[1] + high58 * BASE4_POWERS[5];

    let ror0 = low1 + high63 * BASE4_POWERS[1];
    let ror1 = low1 * BASE4_POWERS[63] + high63;
    let ror8 = low8 * BASE4_POWERS[56] + high56;
    let ror19 = low19 * BASE4_POWERS[45] + high45;
    let ror61 = low61 * BASE4_POWERS[3] + high3;
    let rshift6 = high58;
    let rshift7 = high57;
    // 1, 8, 19, 61
    // 6, 7

    EncodedWitness { raw: w, w: ror0, ror1, ror8, ror19, ror61, rshift6, rshift7 }
}

// fn encode_first_message_extension(w15: Field) -> EncodedS0 {
//     //Safety: split input into slices with the following bit sizes:
//     //        1,6,1,8,8,8,8,8,8,8
//     //        We need to validate the correctness of these slice claims by asserting their sum equals `w15`,
//     //        and we also need to validate the bit range of each slice
//     //        (we get an implicit range constraint for free by indexing our BASE4_ENCODE_TABLE lookup tables)
//     let s = unsafe { __decompose_w15(w15) };

//     let mut reconstructed = s[9];
//     reconstructed *= 256;
//     reconstructed += s[8];
//     reconstructed *= 256;
//     reconstructed += s[7];
//     reconstructed *= 256;
//     reconstructed += s[6];
//     reconstructed *= 256;
//     reconstructed += s[5];
//     reconstructed *= 256;
//     reconstructed += s[4];
//     reconstructed *= 256;
//     reconstructed += s[3];
//     reconstructed *= 2;
//     reconstructed += s[2];
//     reconstructed *= 64;
//     reconstructed += s[1];
//     reconstructed *= 2;
//     reconstructed += s[0];
//     assert_eq(reconstructed, w15); // 7 gates?

//     let mut base4_encoded_slices: [Field; 10] = [0; 10];
//     // 18 gates?
//     base4_encoded_slices[0] = BASE4_ENCODE_1BIT_TABLE[s[0]];
//     base4_encoded_slices[1] = BASE4_ENCODE_6BIT_TABLE[s[1]];
//     base4_encoded_slices[2] = BASE4_ENCODE_1BIT_TABLE[s[2]];
//     base4_encoded_slices[3] = BASE4_ENCODE_8BIT_TABLE[s[3]];
//     base4_encoded_slices[4] = BASE4_ENCODE_8BIT_TABLE[s[4]];
//     base4_encoded_slices[5] = BASE4_ENCODE_8BIT_TABLE[s[5]];
//     base4_encoded_slices[6] = BASE4_ENCODE_8BIT_TABLE[s[6]];
//     base4_encoded_slices[7] = BASE4_ENCODE_8BIT_TABLE[s[7]];
//     base4_encoded_slices[8] = BASE4_ENCODE_8BIT_TABLE[s[8]];
//     base4_encoded_slices[9] = BASE4_ENCODE_8BIT_TABLE[s[9]];

//     let mut high56 = base4_encoded_slices[9];
//     high56 *= BASE4_POWERS[8];
//     high56 += base4_encoded_slices[8];
//     high56 *= BASE4_POWERS[8];
//     high56 += base4_encoded_slices[7];
//     high56 *= BASE4_POWERS[8];
//     high56 += base4_encoded_slices[6];
//     high56 *= BASE4_POWERS[8];
//     high56 += base4_encoded_slices[5];
//     high56 *= BASE4_POWERS[8];
//     high56 += base4_encoded_slices[4];
//     high56 *= BASE4_POWERS[8];
//     high56 += base4_encoded_slices[3];

//     let mut high57 = high56 * BASE4_POWERS[1] + base4_encoded_slices[2];

//     let mut high63 = high57 * BASE4_POWERS[6] + base4_encoded_slices[1];

//     let mut low1 = base4_encoded_slices[0];
//     let mut low8 = low1
//         + base4_encoded_slices[1] * BASE4_POWERS[1]
//         + base4_encoded_slices[2] * BASE4_POWERS[7];

//     let w_ror1 = low1 * BASE4_POWERS[63] + high63;
//     let w_ror8 = low8 * BASE4_POWERS[56] + high56;
//     let w_rshift7 = high57;
//     let w_ror0 = low8 + high56 * BASE4_POWERS[8];

//     EncodedS0 { raw: w15, w: w_ror0, w_ror1, w_ror8, w_rshift7 }
// }

pub(crate) fn encode_e(e: Field) -> EncodedChoose {
    //Safety: split input into slices with the following bit sizes:
    //        8,6,4,6,8,9,7,8,8
    //        We need to validate the correctness of these slice claims by asserting their sum equals `a`,
    //        and we also need to validate the bit range of each slice
    //        (we get an implicit range constraint for free by indexing our BASE4_ENCODE_TABLE lookup tables)
    let s = unsafe { decompose_e(e) };

    let mut reconstructed = s[8];
    reconstructed *= 256;
    reconstructed += s[7];
    reconstructed *= 128;
    reconstructed += s[6];
    reconstructed *= 512;
    reconstructed += s[5];
    reconstructed *= 256;
    reconstructed += s[4];
    reconstructed *= 64;
    reconstructed += s[3];
    reconstructed *= 16;
    reconstructed += s[2];
    reconstructed *= 64;
    reconstructed += s[1];
    reconstructed *= 256;
    reconstructed += s[0];
    assert_eq(reconstructed, e); // 7 gates?

    // 8, 6, 4, 6, 8, 9, 7, 8, 8

    let mut base4_encoded_slices: [Field; 9] = [0; 9];
    // 18 gates?
    base4_encoded_slices[0] = BASE4_ENCODE_8BIT_TABLE[s[0]];
    base4_encoded_slices[1] = BASE4_ENCODE_6BIT_TABLE[s[1]];
    base4_encoded_slices[2] = BASE4_ENCODE_4BIT_TABLE[s[2]];
    base4_encoded_slices[3] = BASE4_ENCODE_6BIT_TABLE[s[3]];
    base4_encoded_slices[4] = BASE4_ENCODE_8BIT_TABLE[s[4]];
    base4_encoded_slices[5] = BASE4_ENCODE_9BIT_TABLE[s[5]];
    base4_encoded_slices[6] = BASE4_ENCODE_7BIT_TABLE[s[6]];
    base4_encoded_slices[7] = BASE4_ENCODE_8BIT_TABLE[s[7]];
    base4_encoded_slices[8] = BASE4_ENCODE_8BIT_TABLE[s[8]];

    // 14, 18, 41

    // 2 gates?
    let mut low14 = base4_encoded_slices[0];
    low14 += base4_encoded_slices[1] * BASE4_POWERS[8];

    let mut low18 = low14 + base4_encoded_slices[2] * BASE4_POWERS[14];

    let mut low41 = base4_encoded_slices[5];
    low41 *= BASE4_POWERS[8];
    low41 += base4_encoded_slices[4];
    low41 *= BASE4_POWERS[6];
    low41 += base4_encoded_slices[3];
    low41 *= BASE4_POWERS[18];
    low41 += low18;

    let mut high23 = base4_encoded_slices[8] * BASE4_POWERS[8];
    high23 += base4_encoded_slices[7];
    high23 *= BASE4_POWERS[7];
    high23 += base4_encoded_slices[6];

    let mut high46 = high23 * BASE4_POWERS[9];
    high46 += base4_encoded_slices[5];
    high46 *= BASE4_POWERS[8];
    high46 += base4_encoded_slices[4];
    high46 *= BASE4_POWERS[6];
    high46 += base4_encoded_slices[3];

    let mut high50 = high46 * BASE4_POWERS[4];
    high50 += base4_encoded_slices[2];

    // 4 gates?
    let ror14 = low14 * BASE4_POWERS[50] + high50;
    let ror18 = low18 * BASE4_POWERS[46] + high46;
    let ror41 = low41 * BASE4_POWERS[23] + high23;
    let e_ror0 = low41 + high23 * BASE4_POWERS[41];
    // 28 36
    // 34 30
    // 39 25
    EncodedChoose { raw: e, e: e_ror0, ror14, ror18, ror41 }
}

pub(crate) fn encode_a(a: Field) -> EncodedMajority {
    //Safety: split input into slices with the following bit sizes:
    //        8,8,8,4,6,5,9,8,8
    //        We need to validate the correctness of these slice claims by asserting their sum equals `a`,
    //        and we also need to validate the bit range of each slice
    //        (we get an implicit range constraint for free by indexing our BASE4_ENCODE_TABLE lookup tables)
    let s = unsafe { decompose_a(a) };

    // 8,8,8,4,6,5,9,8,8
    // 7 gates?
    let mut reconstructed = s[8];
    reconstructed *= 256;
    reconstructed += s[7];
    reconstructed *= 512;
    reconstructed += s[6];
    reconstructed *= 32;
    reconstructed += s[5];
    reconstructed *= 64;
    reconstructed += s[4];
    reconstructed *= 16;
    reconstructed += s[3];
    reconstructed *= 256;
    reconstructed += s[2];
    reconstructed *= 256;
    reconstructed += s[1];
    reconstructed *= 256;
    reconstructed += s[0];
    assert_eq(reconstructed, a);

    let mut base4_encoded_slices: [Field; 9] = [0; 9];
    // 18 gates?

    base4_encoded_slices[0] = BASE4_ENCODE_8BIT_TABLE[s[0]];
    base4_encoded_slices[1] = BASE4_ENCODE_8BIT_TABLE[s[1]];
    base4_encoded_slices[2] = BASE4_ENCODE_8BIT_TABLE[s[2]];
    base4_encoded_slices[3] = BASE4_ENCODE_4BIT_TABLE[s[3]];
    base4_encoded_slices[4] = BASE4_ENCODE_6BIT_TABLE[s[4]];
    base4_encoded_slices[5] = BASE4_ENCODE_5BIT_TABLE[s[5]];
    base4_encoded_slices[6] = BASE4_ENCODE_9BIT_TABLE[s[6]];
    base4_encoded_slices[7] = BASE4_ENCODE_8BIT_TABLE[s[7]];
    base4_encoded_slices[8] = BASE4_ENCODE_8BIT_TABLE[s[8]];

    // 2 gates?
    let mut low28 = base4_encoded_slices[3] * BASE4_POWERS[8];
    low28 += base4_encoded_slices[2];
    low28 *= BASE4_POWERS[8];
    low28 += base4_encoded_slices[1];
    low28 *= BASE4_POWERS[8];
    low28 += base4_encoded_slices[0];
    // 1 gate?
    let mut low34 = low28 + base4_encoded_slices[4] * BASE4_POWERS[28];

    // 1 gate?
    let mut low39 = low34 + base4_encoded_slices[5] * BASE4_POWERS[34];

    // 1 gate?
    let four_pow_9: Field = 0x40000;

    let mut high25 = base4_encoded_slices[8] * BASE4_POWERS[17];
    high25 += base4_encoded_slices[7] * four_pow_9;
    high25 += base4_encoded_slices[6];

    // 1 gate?
    let mut high30 = high25 * BASE4_POWERS[5] + base4_encoded_slices[5];

    // 1 gate?
    let mut high36 = high30 * BASE4_POWERS[6] + base4_encoded_slices[4];

    // 4 gates?
    let ror28 = (low28 * BASE4_POWERS[36]) + high36;
    let ror34 = (low34 * BASE4_POWERS[30]) + high30;
    let ror39 = (low39 * BASE4_POWERS[25]) + high25;
    let a_ror0 = low39 + (high25 * BASE4_POWERS[39]);

    EncodedMajority { raw: a, a: a_ror0, ror28, ror34, ror39 }
}

unconstrained fn __split_into_base4_5bit_slices(encoded: Field) -> [Field; 13] {
    let mut acc = encoded as u128;

    let mut slices: [Field; 13] = [0; 13];

    for i in 0..13 {
        slices[i] = (acc & 1023) as Field;
        acc >>= 10;
    }

    slices
}

pub(crate) fn decode_majority(a: Field, b: Field, c: Field) -> Field {
    let encoded = a + b + c;
    // Safety: split input into base4 5bit slices (i.e. 10 bit slices)
    //         we validate the sum of the slices equals the input.
    //         indexing `BASE4_MAJORITY_DECODE_5BIT_TABLE` by each slice is an implicit range check
    let slices = unsafe { __split_into_base4_5bit_slices(encoded) };
    let mut reconstructed: Field = 0;
    let mut decoded: Field = 0;
    for i in 0..13 {
        reconstructed *= 1024;
        reconstructed += slices[12 - i];
        decoded *= 32;
        decoded += BASE4_MAJORITY_DECODE_5BIT_TABLE[slices[12 - i]];
    }
    assert_eq(reconstructed, encoded);

    decoded
}

pub(crate) fn decode_choose(e: Field, f: Field, g: Field) -> Field {
    let two_e_plus_g = e + e + g;
    let e_plus_f = e + f;
    // Safety: split input into base4 5bit slices (i.e. 10 bit slices)
    //         we validate the sum of the slices equals the input.
    //         indexing `BASE4_PARTIAL_CHOOSE_DECODE_5BIT_TABLE` by each slice is an implicit range check
    let lhs_slices = unsafe { __split_into_base4_5bit_slices(two_e_plus_g) };
    let mut reconstructed: Field = 0;
    let mut decoded_lhs: Field = 0;
    for i in 0..13 {
        reconstructed *= 1024;
        reconstructed += lhs_slices[12 - i];
        decoded_lhs *= 32;
        decoded_lhs += BASE4_PARTIAL_CHOOSE_DECODE_5BIT_TABLE[lhs_slices[12 - i]];
    }
    assert_eq(reconstructed, two_e_plus_g);

    // Safety: split input into base4 5bit slices (i.e. 10 bit slices)
    //         we validate the sum of the slices equals the input.
    //         indexing `BASE4_MAJORITY_DECODE_5BIT_TABLE` by each slice is an implicit range check
    let rhs_slices = unsafe { __split_into_base4_5bit_slices(e_plus_f) };
    let mut reconstructed: Field = 0;
    let mut decoded_rhs: Field = 0;
    for i in 0..13 {
        reconstructed *= 1024;
        reconstructed += rhs_slices[12 - i];
        decoded_rhs *= 32;
        decoded_rhs += BASE4_MAJORITY_DECODE_5BIT_TABLE[rhs_slices[12 - i]];
    }
    assert_eq(reconstructed, e_plus_f);

    decoded_lhs + decoded_rhs
}

pub(crate) fn decode_xor(encoded: Field) -> Field {
    //Safety: split input into 5-bit slices.
    //        Because the input is in base4, we actually obtain 10-bit slices
    //        We need to validate the correctness of these slice claims by asserting their sum equals `encoded`,
    //        and we also need to validate the bit range of each slice
    //        (we get an implicit range constraint for free by indexing our BASE4_XOR_DECODE_5BIT_TABLE lookup table)
    let slices = unsafe { __split_into_base4_5bit_slices(encoded) };

    // println(f"encoded slices {slices}");
    let mut reconstructed: Field = 0;
    let mut decoded: Field = 0;
    for i in 0..13 {
        reconstructed *= 1024;
        reconstructed += slices[12 - i];
        decoded *= 32;
        decoded += BASE4_XOR_DECODE_5BIT_TABLE[slices[12 - i]];
    }
    assert_eq(reconstructed, encoded);

    decoded
}

#[test]
fn test_encode_message_extension() {
    let expected: u64 = 0x7ffffaffeffff2ff;
    let encoded = encode_message_extension(expected as Field);

    let w_ror1: u64 = (expected >> 1) + ((expected & 1) << (64 - 1));
    let w_ror8 = (expected >> 8) + ((expected & 255) << (64 - 8));
    let w_rshift7 = (expected >> 7);
    let w_ror19 = (expected >> 19) + ((expected & 0x7ffff) << (64 - 19));
    let w_ror61 = (expected >> 61) + ((expected & 0x1fffffffffffffff) << (64 - 61));
    let w_rshift6 = (expected >> 6);

    let result = decode_xor(encoded.w);

    let decoded_ror1: Field = decode_xor(encoded.ror1);
    let decoded_ror8: Field = decode_xor(encoded.ror8);
    let decoded_rshift7: Field = decode_xor(encoded.rshift7);
    let decoded_ror19: Field = decode_xor(encoded.ror19);
    let decoded_ror61: Field = decode_xor(encoded.ror61);
    let decoded_rshift6: Field = decode_xor(encoded.rshift6);

    assert_eq(result, expected as Field);
    assert_eq(decoded_ror1, w_ror1 as Field);
    assert_eq(decoded_ror8, w_ror8 as Field);
    assert_eq(decoded_ror19, w_ror19 as Field);
    assert_eq(decoded_ror61, w_ror61 as Field);
    assert_eq(decoded_rshift6, w_rshift6 as Field);
    assert_eq(decoded_rshift7, w_rshift7 as Field);
}

#[test]
fn test_encode_e() {
    let expected: u64 = 0x7ffffaffeffff2ff;
    let e_encoded = encode_e(expected as Field);

    let ror_14 = (expected >> 14) + ((expected & 0x3fff) << (64 - 14));
    let ror_18 = (expected >> 18) + ((expected & 0x3ffff) << (64 - 18));
    let ror_41 = (expected >> 41) + ((expected & 0x1ffffffffff) << (64 - 41));

    let result = decode_xor(e_encoded.e);
    let decoded_ror14: Field = decode_xor(e_encoded.ror14);
    let decoded_ror18: Field = decode_xor(e_encoded.ror18);
    let decoded_ror41: Field = decode_xor(e_encoded.ror41);

    assert_eq(result, expected as Field);
    assert_eq(decoded_ror14, ror_14 as Field);
    assert_eq(decoded_ror18, ror_18 as Field);
    assert_eq(decoded_ror41, ror_41 as Field);
}

#[test]
fn test_encode_a() {
    let expected: u64 = 0x7ffffaffeffff2ff; // two pow 52
    let a_encoded = encode_a(expected as Field);

    // when encoded into base 4. a 64 bit value equals 128 bits?

    let ror_28 = (expected >> 28) + ((expected & 0x0fffffff) << (64 - 28));
    let ror_34 = (expected >> 34) + ((expected & 0x3ffffffff) << (64 - 34));
    let ror_39 = (expected >> 39) + ((expected & 0x7fffffffff) << (64 - 39));

    let result = decode_xor(a_encoded.a);
    let decoded_ror28: Field = decode_xor(a_encoded.ror28);
    let decoded_ror34: Field = decode_xor(a_encoded.ror34);
    let decoded_ror39: Field = decode_xor(a_encoded.ror39);

    assert_eq(result, expected as Field);
    assert_eq(decoded_ror28, ror_28 as Field);
    assert_eq(decoded_ror34, ror_34 as Field);
    assert_eq(decoded_ror39, ror_39 as Field);
}

#[test]
fn test_majority() {
    let a: u64 = 0x7ffffaffeffff2ff;
    let b: u64 = 0xf23ff3900baa22ff;
    let c: u64 = 0x2439823847ffeeaa;

    let a_enc = encode_a(a as Field);
    let b_enc = encode_a(b as Field);
    let c_enc = encode_a(c as Field);

    let result = decode_majority(a_enc.a, b_enc.a, c_enc.a);

    let expected = ((a & b) ^ (a & c) ^ (b & c)) as Field;

    assert_eq(result, expected);
}

#[test]
fn test_choose() {
    let e: u64 = 0x7ffffaffeffff2ff;
    let f: u64 = 0xf23ff3900baa22ff;
    let g: u64 = 0xf439823847ffeeaa;

    let e_enc = encode_e(e as Field);
    let f_enc = encode_e(f as Field);
    let g_enc = encode_e(g as Field);

    let result = decode_choose(e_enc.e, f_enc.e, g_enc.e);

    let expected = ((!e & g) ^ (e & f)) as Field;

    assert_eq(result, expected);
}
