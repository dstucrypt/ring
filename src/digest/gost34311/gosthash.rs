use super::gost89;
use super::sbox;

pub struct GostHash {
    pub ctx: gost89::Gost89,
    pub h: [u8; 32],
    pub s: [u8; 32],
    pub len: u64,
}

pub fn init(sbox: sbox::Sbox) -> GostHash {
    let key: [u32; 8] = [0; 8];
    let ctx = gost89::init(sbox, key);
    return GostHash {ctx: ctx, h: [0; 32], s: [0; 32], len: 0};
}

pub fn init_default() -> GostHash {
    return init(sbox::unpack(sbox::DSTU_SBOX));
}

fn swap_bytes (w: &[u8], k: &mut [u8]) {
    let mut i: usize = 0;
    let mut j: usize;

    while i < 4 {
        j = 0;
        while j < 8 {
            k[ i + 4 * j ] = w[ 8 * i +j ];
            j += 1;
        }
        i += 1;
    }

}

fn xor_blocks (a: &[u8], b: &[u8], out: &mut [u8], len: usize) {
    let mut i: usize = 0;
    while i < len {
        out[i] = a[i] ^ b[i];
        i += 1;
    }
}

fn circle_xor8(w: &[u8], k: &mut[u8]) {
    let mut i = 0;
    let buf: [u8; 8] = [w[0], w[1], w[2], w[3],
                        w[4], w[5], w[6], w[7]];
    while i < 24 {
        k[i] = w[i + 8];
        i += 1;
    }

    i = 0;
    while i < 8 {
        k[i+24] = buf[i] ^k [i];
        i += 1;
    }
}

fn transform_3(data: &mut[u8]) {
    let acc: u32;
    acc = (
        data[0] ^ data[2] ^ data[4] ^ data[6] ^ data[24] ^ data[30]
    ) as u32 | ((
      (
        data[1] ^ data[3] ^ data[5] ^ data[7] ^ data[25] ^ data[31]
      ) as u32) << 8
    );
    let mut i: usize = 0;
    while i < 30 {
        data[i] = data[i + 2];
        i += 1;
    }
    data[30]= (acc & 0xff) as u8;
    data[31]= (acc >> 8) as u8;
}


fn hash_step(ctx: &gost89::Gost89, h: &mut [u8], m: &[u8]) {
    let mut u: [u8; 32] = [0; 32];
    let mut w: [u8; 32] = [0; 32];
    let mut v: [u8; 32] = [0; 32];
    let mut s: [u8; 32] = [0; 32];
    let mut key: [u8; 32] = [0; 32];

    xor_blocks(&h, &m, &mut w, 32);
    swap_bytes(&w, &mut key);

    gost89::encrypt(&gost89::set_key(ctx, key), h, &mut s);
            
    /* Compute second key*/
    circle_xor8(&h, &mut u);
    circle_xor8(&m, &mut v);
    circle_xor8(&v.clone(), &mut v);

    xor_blocks(&u, &v, &mut w, 32);
    swap_bytes(&w, &mut key);

    gost89::encrypt(&gost89::set_key(ctx, key), &h[8..], &mut s[8..]);

    /* compute third key */
    circle_xor8(&u.clone(), &mut u);
    u[31] = !u[31]; u[29] = !u[29]; u[28] = !u[28]; u[24] = !u[24];
    u[23] = !u[23]; u[20] = !u[20]; u[18] = !u[18]; u[17] = !u[17];
    u[14] = !u[14]; u[12] = !u[12]; u[10] = !u[10]; u[ 8] = !u[ 8];
    u[ 7] = !u[ 7]; u[ 5] = !u[ 5]; u[ 3] = !u[ 3]; u[ 1] = !u[ 1];
    circle_xor8(&v.clone(), &mut v);
    circle_xor8(&v.clone(), &mut v);
    xor_blocks(&u, &v, &mut w, 32);
    swap_bytes(&w, &mut key);

    gost89::encrypt(&gost89::set_key(ctx, key), &h[16..], &mut s[16..]);

    /* Compute fourth key */
    circle_xor8(&u.clone(), &mut u);
    circle_xor8(&v.clone(), &mut v);
    circle_xor8(&v.clone(), &mut v);
    xor_blocks(&u, &v, &mut w, 32);
    swap_bytes(&w, &mut key);

    /* Encrypt last 8 bytes with fourth key */
    gost89::encrypt(&gost89::set_key(ctx, key), &h[24..], &mut s[24..]);

    let mut i = 0;
    while i < 12 {
        transform_3(&mut s);
        i += 1;
    }

    xor_blocks(&s.clone(), &m, &mut s, 32);
    transform_3(&mut s);
    xor_blocks(&s.clone(), &h, &mut s, 32);
    let mut i = 0;
    while i < 61 {
        transform_3(&mut s);
        i += 1;
    }

    let mut i: usize = 0;
    while i < 32 {
        h[i] = s[i];
        i += 1;
    }

}

fn add_blocks(n: usize, left: &mut[u8], right: &[u8]) {
    let mut i: usize = 0;
    let mut carry: u32 = 0;
    let mut sum;

    while i < n  {
        sum = (left[i] as u32) + (right[i] as u32) + carry;
        left[i] = (sum & 0xff) as u8;
        carry = sum >> 8;

        i+= 1;
    }
}
 

/// Update hash with value of any size
pub fn update(hash: &mut GostHash, data: &[u8]) {
    let mut offset = 0;
    let mut data_left = data.len();
    while data_left >= 32 {
        hash_step(&hash.ctx, &mut hash.h, &data[offset..offset+32]);
        add_blocks(32, &mut hash.s, &data[offset..offset+32]);
        offset += 32;
        hash.len += 32;
        data_left -= 32;
    }

    if data_left > 0 {
        let mut leftover: [u8; 32] = [0; 32];
        let mut i: usize = 0;
        while i < data_left {
            leftover[i] = data[offset + i];

            i += 1;
        }
        hash_step(&hash.ctx, &mut hash.h, &leftover);
        add_blocks(32, &mut hash.s, &leftover);
        hash.len += data_left as u64;
    }
}

/// Finalize hash. Update should not be called after this
pub fn finish(hash: &GostHash, out: &mut [u8]) {
    let mut len_block: [u8; 32] = [0; 32];
    let mut len = hash.len << 3;
    let mut i: usize = 0;

    let mut h = hash.h;
    let s = hash.s;

    while len > 0 {
        len_block[i] = (len & 0xFF) as u8;
        len = len >> 8;
        i += 1;
    }

    hash_step(&hash.ctx, &mut h, &len_block);
    hash_step(&hash.ctx, &mut h, &s);

    i = 0;
    while i < 32 {
        out[i] = h[i];
        i += 1;
    }
}
