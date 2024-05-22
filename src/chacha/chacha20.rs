const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const BLOCK_LENGTH: usize = 64;

pub type Key = [u8; KEY_LENGTH];
pub type Nonce = [u8; NONCE_LENGTH];

pub struct ChaCha20Block {
    state: [u32; 16],
}

pub struct ChaCha20 {
    key: Key,
    nonce: Nonce,
    counter: u32,
}

impl ChaCha20Block {

    ///
    /// The ChaCha20Block constructor initializes the state array with the provided
    /// key and nonce.  The key is 256-bits and the nonce is 64-bits.  The state
    /// array is initialized as follows:
    ///
    /// 1. The first four words are constants: 0x61707865, 0x3320646e, 0x79622d32, and 0x6b206574.
    /// 2. The next eight words (4-11) are taken from the 256-bit key by reading the bytes in little-endian order, in 4-byte chunks.
    /// 3. Word 12 is a block counter.  Since each block is 64 bytes, a 32-bit word allows for encrypting 2^6B * 2^32 = 2^38B = 256GB.
    /// 4. Words 13-15 are a nonce, which should not be repeated for the same key.
    /// They are taken by reading the bytes in little-endian order, in 4-byte chunks.
    ///
    /// Visual representation as a matrix of the state array:
    /// 
    /// ```
    /// cccccccc  cccccccc  cccccccc  cccccccc
    /// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    /// kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
    /// bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
    /// ```
    ///
    /// c=constant k=key b=blockcount n=nonce
    ///
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.3)
    ///
    pub fn new(key: Key, nonce: Nonce, counter: u32) -> Self {
        let mut state = [0u32; 16];
        // Add the constants to the state array
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        

        // Add the key to the state array
        for (i, key_part) in key.chunks_exact(4).into_iter().enumerate() {
            state[4+i] = u32::from_le_bytes(key_part.try_into().unwrap());
        }

        // Add the block counter to the state array
        state[12] = counter;

        // Add the nonce to the state array
        for (i, nonce_part) in nonce.chunks_exact(4).into_iter().enumerate() {
            state[13+i] = u32::from_le_bytes(nonce_part.try_into().unwrap());
        }

        ChaCha20Block { state }
    }

    ///
    /// The basic operation of the ChaCha algorithm is the quarter round.  It
    /// operates on four 32-bit unsigned integers, denoted a, b, c, and d.
    /// The operation is as follows:
    ///
    /// 1.  a += b; d ^= a; d <<= 16;
    /// 2.  c += d; b ^= c; b <<= 12;
    /// 3.  a += b; d ^= a; d <<= 8;
    /// 4.  c += d; b ^= c; b <<= 7;
    ///
    /// Where all operations are wrapping additions, and the left shift is a
    /// circular rotation.
    ///
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.1)
    ///
    pub fn quarter_round(&mut self, x: usize, y: usize, z: usize, w: usize) {
        let mut a = self.state[x];
        let mut b = self.state[y];
        let mut c = self.state[z];
        let mut d = self.state[w];
        
        // 1. a += b; d ^= a; d <<= 16;
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(16);

        // 2. c += d; b ^= c; b <<= 12;
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(12);

        // 3. a += b; d ^= a; d <<= 8;
        a = a.wrapping_add(b); d ^= a; d = d.rotate_left(8);

        // 4. c += d; b ^= c; b <<= 7;
        c = c.wrapping_add(d); b ^= c; b = b.rotate_left(7);

        self.state[x] = a;
        self.state[y] = b;
        self.state[z] = c;
        self.state[w] = d;
    }


    ///
    /// The ChaCha20 block function is the core of the ChaCha20 algorithm.  It
    /// consists of 10 rounds of quarter rounds, before adding the working state
    /// to the current state.
    ///
    /// The block function is as follows:
    ///
    /// 1.  The current state is copied to an old state.
    /// 2.  80 rounds of quarter rounds are performed on the working state.
    /// 3.  The old state is added to the working state.
    ///
    /// [Source](https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.1)
    ///
    pub fn block(&mut self) {
        let old_state = self.state.clone();

        // 80 rounds of quarter rounds
        for _ in 0..10 {
            self.quarter_round(0, 4, 8, 12);
            self.quarter_round(1, 5, 9, 13);
            self.quarter_round(2, 6, 10, 14);
            self.quarter_round(3, 7, 11, 15);
            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }

        // state += working_state
        self.state.iter_mut().zip(&old_state).for_each(|(x, y)| {
            *x = x.wrapping_add(*y);
        });
    }

    ///
    /// Generates the keystream from the state by running ChaCha20.
    ///
    pub fn get_keystream(&mut self) -> [u8; BLOCK_LENGTH] {
        self.block();
        self.state.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>().try_into().unwrap()
    }

    pub fn encrypt(&mut self, data: &[u32]) -> [u32; 16] {
        self.block();
        
        let old_state = self.state.clone();
        let mut key_stream = old_state.map(|x| u32::from_be_bytes(x.to_le_bytes()));
        key_stream.iter_mut().zip(&data[..16]).for_each(|(x, &y)| {
            *x ^= y;
        });
        key_stream
    }

    ///
    /// Gets the current state of the ChaCha20 cipher.
    ///
    pub fn get_state(&self) -> &[u32; 16] {
        &self.state
    }
}

impl ChaCha20 {
    pub fn new(key: Key, nonce: Nonce) -> Self {
        ChaCha20 { key, nonce, counter: 1 }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let blocks = (data.len() + BLOCK_LENGTH - 1) / BLOCK_LENGTH;
        let keystream = (0..blocks).flat_map(|i| {
            let mut block = ChaCha20Block::new(self.key, self.nonce, self.counter + i as u32);
            block.get_keystream()
        }).collect::<Vec<u8>>();
        self.counter += blocks as u32;

        keystream.iter().zip(data).map(|(x, y)| x ^ y).collect::<Vec<u8>>()
    }
}