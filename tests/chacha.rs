#[cfg(test)]
mod chacha_tests {
    extern crate seal_rs;

    use seal_rs::chacha::ChaCha20;

    const TEST_KEY: [u32; 8] = [
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
        0x1c1d1e1f,
    ];
    const TEST_NONCE: [u32; 3] = [0x00000009, 0x0000004a, 0x00000000];

    ///
    /// Simple test to verify that the quarter round operation is working correctly.
    ///
    /// Taken from the RFC7539 specification.
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.1.1)
    ///
    #[test]
    fn simple_quarter_round_test() {
        let key = [0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567, 0, 0, 0, 0];
        let mut cipher = ChaCha20::new(key, TEST_NONCE);
        cipher.quarter_round(4, 5, 6, 7);

        let result_state = cipher.get_state();
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
        let mut cipher = ChaCha20::new(TEST_KEY, TEST_NONCE);
        cipher.block();

        let result_state = cipher.get_state();

        let expected = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ];

        assert_eq!(result_state, &expected);
    }

    ///
    /// Simple test to verify that the encrypt operation is working correctly.
    ///
    /// Taken from the RFC7539 specification.
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.4.2)
    ///
    #[test]
    fn simple_encrypt_test() {
        let nonce = [0x00000000, 0x0000004a, 0x00000000];

        let mut cipher = ChaCha20::new(TEST_KEY, nonce);

        let result = cipher.encrypt(&[
            0x4c616469, 0x65732061, 0x6e642047, 0x656e746c, 0x656d656e, 0x206f6620, 0x74686520,
            0x636c6173, 0x73206f66, 0x20273939, 0x3a204966, 0x20492063, 0x6f756c64, 0x206f6666,
            0x65722079, 0x6f75206f,
        ]);
        result.iter().for_each(|x| print!("{:08x} ", x));

        // let expected = [
        //     0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
        //     0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
        //     0xe883d0cb, 0x4e3c50a2,
        // ];

        // assert_eq!(result_state, &expected);
    }
}
