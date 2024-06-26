#[cfg(test)]
mod chacha_tests {
    extern crate armadillo;

    use hex_literal::hex;

    use armadillo::poly::{poly1305_mac, poly1305_r_clamp, R};

    const TEST_KEY: [u8; 32] =
        hex!("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    const TEST_DATA: [u8; 34] =
        hex!("43727970746f6772617068696320466f72756d2052657365617263682047726f7570");

    ///
    /// Simple test to verify that the clamp operation is working correctly.
    ///
    /// Taken from the RFC7539 specification.
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.5)
    ///
    #[test]
    fn simple_clamp_test() {
        let r: R = 0xffffffffffffffffffffffffffffffff;
        let clamped = poly1305_r_clamp(r).to_le_bytes();
        // r[3], r[7], r[11], and r[15] are required to have their top four
        // bits clear (be smaller than 16)
        assert!(clamped[3] < 16);
        assert!(clamped[7] < 16);
        assert!(clamped[11] < 16);
        assert!(clamped[15] < 16);
        // r[4], r[8], and r[12] are required to have their bottom two bits
        // clear (be divisible by 4)
        assert!(clamped[4] % 4 == 0);
        assert!(clamped[8] % 4 == 0);
        assert!(clamped[12] % 4 == 0);
    }

    #[test]
    fn simple_poly1305_mac_test() {
        let expected = hex!("a8061dc1305136c6c22b8baf0c0127a9");
        let code = poly1305_mac(TEST_KEY, &TEST_DATA);

        assert_eq!(code, expected);
    }
}
