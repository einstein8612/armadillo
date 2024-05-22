pub type R = u128;
pub type S = u128;
pub type Key = [u8; 32];

///
/// R must be clamped before it is used in the Poly1305 function.
///
/// This is done using the following steps:
///
/// * r(3), r(7), r(11), and r(15) are required to have their top four
/// bits clear (be smaller than 16)
/// * r(4), r(8), and r(12) are required to have their bottom two bits
/// clear (be divisible by 4)
///
/// This method was adapted from poly1305aes_test_clamp.c version 20050207
/// D. J. Bernstein
/// Public domain.
/// 
/// Summarising the method into a single and for performance reasons
///
/// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.5)
///
pub fn poly1305_r_clamp(r: R) -> R {
    r & 0x0ffffffc0ffffffc0ffffffc0fffffff
}



// clamp(r): r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
// poly1305_mac(msg, key):
//    r = (le_bytes_to_num(key[0..15])
//    clamp(r)
//    s = le_num(key[16..31])
//    accumulator = 0
//    p = (1<<130)-5
//    for i=1 upto ceil(msg length in bytes / 16)
//       n = le_bytes_to_num(msg[((i-1)*16)..(i*16)] | [0x01])
//       a += n
//       a = (r * a) % p
//       end
//    a += s
//    return num_to_16_le_bytes(a)
//    end
pub fn poly1305_mac(key: Key)  {
    let r = poly1305_r_clamp(u128::from_le_bytes(key[0..16].try_into().unwrap()));
    let s = u128::from_le_bytes(key[16..32].try_into().unwrap());

    let accumulator = 0;
    let p = (1u128 << 130) - 5;

    println!("Key: {:x}", u128::from_le_bytes(key[0..16].try_into().unwrap()));
}