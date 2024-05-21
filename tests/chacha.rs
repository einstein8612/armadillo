#[cfg(test)]
mod chacha_tests {
    extern crate seal_rs;

    use hex_literal::hex;

    use seal_rs::chacha::{ChaCha20, ChaCha20Block};

    const TEST_KEY: [u8; 32] = hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const TEST_NONCE: [u8; 12] = hex!("000000090000004a00000000");

    ///
    /// Simple test to verify that the quarter round operation is working correctly.
    ///
    /// Taken from the RFC7539 specification.
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.1.1)
    ///
    #[test]
    fn simple_quarter_round_test() {
        let key: [u8; 32] = hex!("1111111104030201436f8d9b6745230100000000000000000000000000000000");
        let mut block = ChaCha20Block::new(key, TEST_NONCE, 1);
        block.quarter_round(4, 5, 6, 7);

        let result_state = block.get_state();
        assert_eq!(result_state[4], 0xea2a92f4);
        assert_eq!(result_state[5], 0xcb1cf8ce);
        assert_eq!(result_state[6], 0x4581472e);
        assert_eq!(result_state[7], 0x5881c4bb);
    }

    ///
    /// Simple test to verify that the block operation is working correctly.
    ///
    /// Taken from the RFC7539 specification.
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.2)
    ///
    #[test]
    fn simple_block_test() {
        let mut block = ChaCha20Block::new(TEST_KEY, TEST_NONCE, 1);
        block.block();

        let result_state = block.get_state();

        let expected = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(result_state, &expected);
    }

    ///
    /// Simple test to verify that the keystream operation is working correctly.
    ///
    /// Taken from the RFC7539 specification.
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.2)
    ///
    #[test]
    fn simple_keystream_test() {
        let mut block = ChaCha20Block::new(TEST_KEY, TEST_NONCE, 1);

        let expected = hex!("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
        assert_eq!(block.get_keystream(), expected)
    }


    ///
    /// Simple test to verify that the encrypt operation is working correctly.
    ///
    /// Taken from the RFC7539 specification.
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.2)
    ///
    #[test]
    fn helloworld_encrypt_test() {
        let nonce = hex!("000000000000004a00000000");
        let mut cipher = ChaCha20::new(TEST_KEY, nonce);

        let expected = hex!("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");
        let ciphertext = cipher.encrypt("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".as_bytes());
        assert_eq!(ciphertext, expected);
    }
}
