const R_LENGTH: usize = 16;


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
/// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.5)
///
pub fn poly1305_r_clamp(r: &mut [u8; R_LENGTH]) {
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}
