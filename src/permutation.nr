use crate::encoding::{
    decode_choose, decode_majority, decode_xor, encode_a, encode_e, encode_message_extension,
    EncodedChoose, EncodedMajority, EncodedWitness,
};

// Size of the message block when packed as 8-byte integer array.
global INT_BLOCK_SIZE: u32 = 16;

type INT_BLOCK = [u64; INT_BLOCK_SIZE];

// The state accumulates the blocks.
// Its overall size is the same as the `HASH`.
type STATE = [u64; 8];

fn extend_witness(witness: [Field; 16]) -> [Field; 80] {
    let mut w: [EncodedWitness; 80] = [EncodedWitness::new(); 80];
    for i in 0..16 {
        w[i] = encode_message_extension(witness[i]);
    }
    // note for improvements:
    // 1: we don't need to re-encode for `i = 79, i = 80`
    // 2: we only need partial re-encoding for i = [65...,78]
    // 3: we only need partial encoding for i = [0,..,13]
    for i in 16..80 {
        let s0 = decode_xor(w[i - 15].ror1 + w[i - 15].ror8 + w[i - 15].rshift7);

        let s1 = decode_xor(w[i - 2].ror19 + w[i - 2].ror61 + w[i - 2].rshift6);

        let new_witness = reduce_modulo_64(w[i - 16].raw + s0 + w[i - 7].raw + s1);

        w[i] = encode_message_extension(new_witness);
    }

    let mut result: [Field; 80] = [0; 80];
    for i in 0..80 {
        result[i] = w[i].raw;
    }
    result
}

fn majority(a: EncodedMajority, b: EncodedMajority, c: EncodedMajority) -> Field {
    let xor_output = decode_xor(a.ror28 + a.ror34 + a.ror39);

    let majority_output = decode_majority(a.a, b.a, c.a);

    xor_output + majority_output
}

fn choose(e: EncodedChoose, f: EncodedChoose, g: EncodedChoose) -> Field {
    let xor_output = decode_xor(e.ror14 + e.ror18 + e.ror41);

    let choose_output = decode_choose(e.e, f.e, g.e);

    xor_output + choose_output
}

struct RoundState {
    a: EncodedMajority,
    b: EncodedMajority,
    c: EncodedMajority,
    d: EncodedMajority,
    e: EncodedChoose,
    f: EncodedChoose,
    g: EncodedChoose,
    h: EncodedChoose,
}

// TODO: initialize this via a constant method that adds no constraints?
impl RoundState {
    fn new() -> Self {
        RoundState {
            a: encode_a(SHA512_INITIAL_HASH_VALUES[0] as Field),
            b: encode_a(SHA512_INITIAL_HASH_VALUES[0] as Field),
            c: encode_a(SHA512_INITIAL_HASH_VALUES[1] as Field),
            d: encode_a(SHA512_INITIAL_HASH_VALUES[2] as Field),
            e: encode_e(SHA512_INITIAL_HASH_VALUES[3] as Field),
            f: encode_e(SHA512_INITIAL_HASH_VALUES[4] as Field),
            g: encode_e(SHA512_INITIAL_HASH_VALUES[5] as Field),
            h: encode_e(SHA512_INITIAL_HASH_VALUES[6] as Field),
        }
    }
}

unconstrained fn __reduce_modulo_64(input: Field) -> (Field, Field) {
    let input128 = input as u128;

    let remainder = input128 & 0xffffffffffffffff;
    let modulus = input128 >> 64;

    (modulus as Field, remainder as Field)
}

fn reduce_modulo_64(input: Field) -> Field {
    // Safety: obtain result and then validate result is correct
    let (modulus, remainder) = unsafe { __reduce_modulo_64(input) };

    modulus.assert_max_bit_size::<8>();
    remainder.assert_max_bit_size::<64>();
    assert_eq(modulus * 0x10000000000000000 + remainder, input);

    remainder
}

fn sha512_compression(_input: INT_BLOCK, _state: STATE) -> STATE {
    let mut message_input: [Field; 16] = [0; 16];
    for i in 0..16 {
        message_input[i] = _input[i] as Field;
    }

    let mut state: RoundState = RoundState {
        a: encode_a(_state[0] as Field),
        b: encode_a(_state[1] as Field),
        c: encode_a(_state[2] as Field),
        d: encode_a(_state[3] as Field),
        e: encode_e(_state[4] as Field),
        f: encode_e(_state[5] as Field),
        g: encode_e(_state[6] as Field),
        h: encode_e(_state[7] as Field),
    };

    let mut w: [Field; 80] = extend_witness(message_input);

    compress(&mut state, w);

    let mut output: STATE = [0; 8];
    output[0] = state.a.raw as u64;
    output[1] = state.b.raw as u64;
    output[2] = state.c.raw as u64;
    output[3] = state.d.raw as u64;
    output[4] = state.e.raw as u64;
    output[5] = state.f.raw as u64;
    output[6] = state.g.raw as u64;
    output[7] = state.h.raw as u64;
    output
}

fn compress(state: &mut RoundState, w: [Field; 80]) {
    for i in 0..80 {
        let S0 = majority(state.a, state.b, state.c);
        let S1 = choose(state.e, state.f, state.g);

        let temp1 = state.h.raw + S1 + (SHA512_ROUND_CONSTANTS[i] as Field) + w[i];
        let temp2 = S0;

        let raw_e = reduce_modulo_64(state.d.raw + temp1);
        let raw_a = reduce_modulo_64(temp1 + temp2);

        let encoded_e = encode_e(raw_e);
        let encoded_a = encode_a(raw_a);
        // 7 adds. when encoding...

        state.h = state.g;
        state.g = state.f;
        state.f = state.e;

        state.d = state.c;
        state.c = state.b;
        state.b = state.a;

        state.e = encoded_e;
        state.a = encoded_a;
    }
}

global SHA384_INITIAL_HASH_VALUES: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];
global SHA512_INITIAL_HASH_VALUES: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

global SHA512_ROUND_CONSTANTS: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

unconstrained fn extend_witness_native(witness: [Field; 16]) -> [u64; 80] {
    let mut w: [u64; 80] = [0; 80];
    for i in 0..16 {
        w[i] = witness[i] as u64;
    }

    for i in 16..80 {
        let w15 = w[i - 15];
        let w2 = w[i - 2];

        let ror1: u64 = (w15 >> 1) + ((w15 & 1) << (64 - 1));
        let ror8 = (w15 >> 8) + ((w15 & 255) << (64 - 8));
        let rshift7 = (w15 >> 7);
        let ror19 = (w2 >> 19) + ((w2 & 0x7ffff) << (64 - 19));
        let ror61 = (w2 >> 61) + ((w2 & 0x1fffffffffffffff) << (64 - 61));
        let rshift6 = (w2 >> 6);

        let s0 = ror1 ^ ror8 ^ rshift7;
        let s1 = ror19 ^ ror61 ^ rshift6;

        let wout =
            ((w[i - 16] as Field) + (s0 as Field) + (w[i - 7] as Field) + (s1 as Field)) as u64;
        w[i] = wout;
    }
    w
}
unconstrained fn compress_native(witness: [Field; 80]) -> [Field; 8] {
    let mut expected: [Field; 8] = [0; 8];

    let mut a: u64 = SHA512_INITIAL_HASH_VALUES[0];
    let mut b: u64 = SHA512_INITIAL_HASH_VALUES[1];
    let mut c: u64 = SHA512_INITIAL_HASH_VALUES[2];
    let mut d: u64 = SHA512_INITIAL_HASH_VALUES[3];
    let mut e: u64 = SHA512_INITIAL_HASH_VALUES[4];
    let mut f: u64 = SHA512_INITIAL_HASH_VALUES[5];
    let mut g: u64 = SHA512_INITIAL_HASH_VALUES[6];
    let mut h: u64 = SHA512_INITIAL_HASH_VALUES[7];
    for i in 0..80 {
        let ror14 = (e >> 14) + ((e & 0x3fff) << (64 - 14));
        let ror18 = (e >> 18) + ((e & 0x3ffff) << (64 - 18));
        let ror41 = (e >> 41) + ((e & 0x1ffffffffff) << (64 - 41));

        let ror28 = (a >> 28) + ((a & 0x0fffffff) << (64 - 28));
        let ror34 = (a >> 34) + ((a & 0x3ffffffff) << (64 - 34));
        let ror39 = (a >> 39) + ((a & 0x7fffffffff) << (64 - 39));

        let S1 = ror14 ^ ror18 ^ ror41;
        let ch = (e & f) ^ ((!e) & g);
        let mut temp1 = h as Field + S1 as Field;
        temp1 += ch as Field;
        temp1 += SHA512_ROUND_CONSTANTS[i] as Field;
        temp1 += witness[i];
        let temp1 = temp1 as u64;
        let S0 = ror28 ^ ror34 ^ ror39;
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = (S0 as Field + maj as Field) as u64;

        h = g;
        g = f;
        f = e;
        e = (d as Field + temp1 as Field) as u64;
        d = c;
        c = b;
        b = a;
        a = (temp1 as Field + temp2 as Field) as u64;
    }
    expected[0] = a as Field;
    expected[1] = b as Field;
    expected[2] = c as Field;
    expected[3] = d as Field;
    expected[4] = e as Field;
    expected[5] = f as Field;
    expected[6] = g as Field;
    expected[7] = h as Field;

    expected
}
#[test]
fn test_compress() {
    let mut witness: [Field; 80] = [0; 80];
    for i in 0..80 {
        witness[i] = SHA512_ROUND_CONSTANTS[i] as Field;
    }
    let mut state: RoundState = RoundState {
        a: encode_a(SHA512_INITIAL_HASH_VALUES[0] as Field),
        b: encode_a(SHA512_INITIAL_HASH_VALUES[1] as Field),
        c: encode_a(SHA512_INITIAL_HASH_VALUES[2] as Field),
        d: encode_a(SHA512_INITIAL_HASH_VALUES[3] as Field),
        e: encode_e(SHA512_INITIAL_HASH_VALUES[4] as Field),
        f: encode_e(SHA512_INITIAL_HASH_VALUES[5] as Field),
        g: encode_e(SHA512_INITIAL_HASH_VALUES[6] as Field),
        h: encode_e(SHA512_INITIAL_HASH_VALUES[7] as Field),
    };

    compress(&mut state, witness);
    // Safety: get native result to compare against
    let expected = unsafe { compress_native(witness) };
    assert_eq(state.a.raw, expected[0]);
    assert_eq(state.b.raw, expected[1]);
    assert_eq(state.c.raw, expected[2]);
    assert_eq(state.d.raw, expected[3]);
    assert_eq(state.e.raw, expected[4]);
    assert_eq(state.f.raw, expected[5]);
    assert_eq(state.g.raw, expected[6]);
    assert_eq(state.h.raw, expected[7]);
}

#[test]
fn test_extend_witness() {
    let mut initial_witness: [Field; 16] = [0; 16];
    for i in 0..16 {
        initial_witness[i] = SHA512_ROUND_CONSTANTS[i] as Field;
    }

    let result = extend_witness(initial_witness);
    // Safety: get native result to compare against
    let expected = unsafe { extend_witness_native(initial_witness) };

    for i in 0..80 {
        assert_eq(result[i], expected[i] as Field);
    }
}

// Convert 128-byte array to array of 16 u64s
fn msg_u8_to_u64(msg: [u8; 128]) -> [u64; 16] {
    let mut msg64: [u64; 16] = [0; 16];

    for i in 0..16 {
        let mut msg_field: Field = 0;
        for j in 0..8 {
            msg_field = msg_field * 256 + msg[128 - 8 * (i + 1) + j] as Field;
        }

        // TODO: fix expensive conversion
        msg64[15 - i] = msg_field as u64;
    }

    msg64
}

global SHA512_LENGTH_PARAMETER_BYTES: u32 = 16;
global SHA512_BLOCK_SIZE: u32 = 128;

// SHA-512/SHA-384 hash function
pub fn digest<let N: u32, let IS_SHA512: u1>(msg: [u8; N]) -> [u8; 64] {
    // noir-fmt:ignore
    let mut h: [u64; 8] = if IS_SHA512 == 1 {
        SHA512_INITIAL_HASH_VALUES
    } else {
        SHA384_INITIAL_HASH_VALUES
    };
    let mut c: [u64; 8] = [0; 8]; // Compression of current message block as sequence of u64
    let mut out_h: [u8; 64] = [0; 64]; // Digest as sequence of bytes

    let num_blocks = (N + SHA512_LENGTH_PARAMETER_BYTES + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE;

    let num_padded_bytes = num_blocks * SHA512_BLOCK_SIZE;
    let mut padded_msg: [u8; ((N + SHA512_LENGTH_PARAMETER_BYTES + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE) * SHA512_BLOCK_SIZE] = [
        0; ((N + SHA512_LENGTH_PARAMETER_BYTES + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE)
            * SHA512_BLOCK_SIZE
    ];

    for i in 0..N {
        padded_msg[i] = msg[i];
    }
    padded_msg[N] = 128;
    // N.B. assuming the message length (in bits) can be covered in 32 bits (approx 16MB message!)
    let length_byte_0: u8 = ((N * 8) as u8) & 255;
    let length_byte_1: u8 = ((N * 8) >> 8) as u8 & 255;
    let length_byte_2: u8 = ((N * 8) >> 16) as u8 & 255;
    let length_byte_3: u8 = ((N * 8) >> 24) as u8 & 255;
    padded_msg[num_padded_bytes - 1] = length_byte_0;
    padded_msg[num_padded_bytes - 2] = length_byte_1;
    padded_msg[num_padded_bytes - 3] = length_byte_2;
    padded_msg[num_padded_bytes - 4] = length_byte_3;

    let mut block_bytes: [u8; 128] = [0; 128];
    for i in 0..num_blocks {
        for j in 0..128 {
            block_bytes[j] = padded_msg[i * 128 + j];
        }
        c = sha512_compression(msg_u8_to_u64(block_bytes), h);
        for j in 0..8 {
            h[j] = std::wrapping_add(h[j], c[j]);
        }
    }

    // Return final hash as byte array
    for j in 0..8 {
        let h_bytes: [u8; 8] = (h[7 - j] as Field).to_le_bytes();
        for k in 0..8 {
            out_h[63 - 8 * j - k] = h_bytes[k];
        }
    }
    out_h
}

pub fn digest_var<let N: u32, let IS_SHA512: u1>(msg: BoundedVec<u8, N>) -> [u8; 64] {
    // noir-fmt:ignore
    let mut h: [u64; 8] = if IS_SHA512 == 1 {
        SHA512_INITIAL_HASH_VALUES
    } else {
        SHA384_INITIAL_HASH_VALUES
    };
    let mut c: [u64; 8] = [0; 8]; // Compression of current message block as sequence of u64
    let mut out_h: [u8; 64] = [0; 64]; // Digest as sequence of bytes

    let num_blocks = (N + SHA512_LENGTH_PARAMETER_BYTES + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE;

    let mut padded_msg: [u8; ((N + SHA512_LENGTH_PARAMETER_BYTES + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE) * SHA512_BLOCK_SIZE] = [
        0; ((N + SHA512_LENGTH_PARAMETER_BYTES + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE)
            * SHA512_BLOCK_SIZE
    ];

    let msg_text = msg.storage();
    for i in 0..N {
        padded_msg[i] = msg_text[i];
    }

    let msg_length = msg.len();

    let num_used_blocks =
        (msg_length + SHA512_LENGTH_PARAMETER_BYTES + SHA512_BLOCK_SIZE) / SHA512_BLOCK_SIZE;

    let num_used_padded_bytes = num_used_blocks * SHA512_BLOCK_SIZE;
    // N.B. this line turns `padded_msg` into a RAM array, which is expensive!
    // A cheaper version of this would pack the inputs into 16-byte words && only modify 1 word,
    // before unpacking into a byte array
    padded_msg[msg_length] = 128;
    // N.B. assuming the message length (in bits) can be covered in 32 bits (approx 16MB message!)
    let length_bytes = (msg_length as Field * 8).to_le_bytes::<4>();
    padded_msg[num_used_padded_bytes - 1] = length_bytes[0];
    padded_msg[num_used_padded_bytes - 2] = length_bytes[1];
    padded_msg[num_used_padded_bytes - 3] = length_bytes[2];
    padded_msg[num_used_padded_bytes - 4] = length_bytes[3];

    let mut output_h: [u64; 8] = h;
    let mut block_bytes: [u8; 128] = [0; 128];
    for i in 0..num_blocks {
        for j in 0..128 {
            block_bytes[j] = padded_msg[i * 128 + j];
        }
        c = sha512_compression(msg_u8_to_u64(block_bytes), h);
        for j in 0..8 {
            h[j] = std::wrapping_add(h[j], c[j]);
        }
        if (i < num_used_blocks) {
            output_h = h;
        }
    }

    // Return final hash as byte array
    for j in 0..8 {
        let h_bytes: [u8; 8] = (output_h[7 - j] as Field).to_le_bytes();
        for k in 0..8 {
            out_h[63 - 8 * j - k] = h_bytes[k];
        }
    }
    out_h
}

// // SHA-512 hash function
// pub fn digest_old<let N: u32>(msg: [u8; N]) -> [u8; 64] {
//     let mut msg_block: [u8; 128] = [0; 128];
//     // noir-fmt:ignore
//     let mut h: [u64; 8] = [7640891576956012808, 13503953896175478587, 4354685564936845355, 11912009170470909681, 5840696475078001361, 11170449401992604703, 2270897969802886507, 6620516959819538809]; // Intermediate hash, starting with the canonical initial value
//     let mut c: [u64; 8] = [0; 8]; // Compression of current message block as sequence of u64
//     let mut out_h: [u8; 64] = [0; 64]; // Digest as sequence of bytes
//     let mut i: u64 = 0; // Message byte pointer
//     for k in 0..msg.len() {
//         // Populate msg_block
//         msg_block[i] = msg[k];
//         i = i + 1;
//         if i == 128 {
//             // Enough to hash block
//             c = sha512_compression(msg_u8_to_u64(msg_block), h);
//             for j in 0..8 {
//                 h[j] = std::wrapping_add(h[j], c[j]);
//             }

//             i = 0;
//         }
//     }
//     // Pad the rest such that we have a [u64; 2] block at the end representing the length
//     // of the message, and a block of 1 0 ... 0 following the message (i.e. [1 << 7, 0, ..., 0]).
//     msg_block[i] = 1 << 7;
//     i += 1;
//     // If i >= 113, there aren't enough bits in the current message block to accomplish this, so
//     // the 1 and 0s fill up the current block, which we then compress accordingly.
//     if i >= 113 {
//         // Not enough bits (128) to store length. Fill up with zeros.
//         if i < 128 {
//             for _i in 113..128 {
//                 if i <= 127 {
//                     msg_block[i] = 0;
//                     i += 1;
//                 }
//             }
//         }
//         println(f"msg block {msg_block}");
//         c = sha512_compression(msg_u8_to_u64(msg_block), h);
//         for j in 0..8 {
//             h[j] = std::wrapping_add(h[j], c[j]);
//         }

//         i = 0;
//     }

//     let len = 8 * msg.len();
//     let len_bytes: [u8; 16] = (len as Field).to_le_bytes();
//     for _i in 0..128 {
//         // In any case, fill blocks up with zeros until the last 128 (i.e. until i = 112).
//         if i < 112 {
//             msg_block[i] = 0;
//             i += 1;
//         } else if i < 128 {
//             for j in 0..16 {
//                 msg_block[127 - j] = len_bytes[j];
//             }
//             i += 16; // Done.
//         }
//     }
//     // Hash final padded block
//     println(f"msg block {msg_block}");
//     c = sha512_compression(msg_u8_to_u64(msg_block), h);
//     for j in 0..8 {
//         h[j] = std::wrapping_add(h[j], c[j]);
//     }
//     // Return final hash as byte array
//     for j in 0..8 {
//         let h_bytes: [u8; 8] = (h[7 - j] as Field).to_le_bytes();
//         for k in 0..8 {
//             out_h[63 - 8 * j - k] = h_bytes[k];
//         }
//     }

//     out_h
// }
