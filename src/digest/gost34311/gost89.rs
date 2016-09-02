use super::sbox;

pub struct Gost89 {
    pub k: [u32; 8],
    pub k87: [u32; 256],
    pub k65: [u32; 256],
    pub k43: [u32; 256],
    pub k21: [u32; 256],
}

#[inline]
fn f(c: &Gost89, x: u32) -> u32 {
    let out = c.k87[(x>>24 & 255) as usize] |
            c.k65[(x>>16 & 255) as usize] |
            c.k43[(x>> 8 & 255) as usize] |
            c.k21[(x & 255) as usize];
    /* Rotate left 11 bits */
    return out<<11 | out>>(32-11);

}

pub fn init(sbox: sbox::Sbox, key: [u32; 8]) -> Gost89 {
    let mut k87: [u32; 256] = [0; 256];
    let mut k65: [u32; 256] = [0; 256];
    let mut k43: [u32; 256] = [0; 256];
    let mut k21: [u32; 256] = [0; 256];

    let mut i = 0;
    while i < 256 {
        k87[i] = ((sbox.k8[i>>4] as u32) << 4 |
                  (sbox.k7[i & 15] as u32)) << 24;
        k65[i] = ((sbox.k6[i>>4] as u32) << 4 |
                  (sbox.k5[i & 15] as u32)) << 16;
        k43[i] = ((sbox.k4[i>>4] as u32) << 4 |
                  (sbox.k3[i &15] as u32)) << 8;
        k21[i] = (sbox.k2[i>>4] as u32) << 4 |
                  sbox.k1[i &15] as u32;

        i = i + 1;
    }

    return Gost89 {k: key, k87: k87, k65: k65, k43: k43, k21: k21};
}

pub fn set_key(ctx: &Gost89, key32: [u8; 32])-> Gost89 {
    let mut key: [u32; 8] = [0; 8];
    let mut i: usize = 0;
    while i < 8 {
        key[i] = key32[i * 4] as u32 |
                 (key32[(i * 4) + 1] as u32) << 8 |
                 (key32[(i * 4) + 2] as u32) << 16 |
                 (key32[(i * 4) + 3] as u32) << 24;

        i += 1;
    }
    return Gost89 {k: key, k87: ctx.k87, k65: ctx.k65, k43: ctx.k43, k21: ctx.k21};

}

#[inline]
fn add(a: u32, b: u32)-> u32 {
    return a.wrapping_add(b);
}

pub fn encrypt(c: &Gost89, inp: &[u8], out: &mut [u8]) {
    let mut n1: u32 = inp[0] as u32 |
                     (inp[1] as u32) << 8 |
                     (inp[2] as u32) <<16 |
                     (inp[3] as u32) <<24;

    let mut n2: u32 = inp[4] as u32 |
                     (inp[5] as u32) << 8 |
                     (inp[6] as u32) << 16 |
                     (inp[7] as u32) <<24;

    /* Instead of swapping halves, swap names each round */
    n2 ^= f(c, add(n1, c.k[0])); n1 ^= f(c, add(n2, c.k[1]));
    n2 ^= f(c, add(n1, c.k[2])); n1 ^= f(c, add(n2, c.k[3]));
    n2 ^= f(c, add(n1, c.k[4])); n1 ^= f(c, add(n2, c.k[5]));
    n2 ^= f(c, add(n1, c.k[6])); n1 ^= f(c, add(n2, c.k[7]));

    n2 ^= f(c, add(n1, c.k[0])); n1 ^= f(c, add(n2, c.k[1]));
    n2 ^= f(c, add(n1, c.k[2])); n1 ^= f(c, add(n2, c.k[3]));
    n2 ^= f(c, add(n1, c.k[4])); n1 ^= f(c, add(n2, c.k[5]));
    n2 ^= f(c, add(n1, c.k[6])); n1 ^= f(c, add(n2, c.k[7]));

    n2 ^= f(c, add(n1, c.k[0])); n1 ^= f(c, add(n2, c.k[1]));
    n2 ^= f(c, add(n1, c.k[2])); n1 ^= f(c, add(n2, c.k[3]));
    n2 ^= f(c, add(n1, c.k[4])); n1 ^= f(c, add(n2, c.k[5]));
    n2 ^= f(c, add(n1, c.k[6])); n1 ^= f(c, add(n2, c.k[7]));

    n2 ^= f(c, add(n1, c.k[7])); n1 ^= f(c, add(n2, c.k[6]));
    n2 ^= f(c, add(n1, c.k[5])); n1 ^= f(c, add(n2, c.k[4]));
    n2 ^= f(c, add(n1, c.k[3])); n1 ^= f(c, add(n2, c.k[2]));
    n2 ^= f(c, add(n1, c.k[1])); n1 ^= f(c, add(n2, c.k[0]));

    out[0] = (n2 & 0xff) as u8;
    out[1] = ((n2 >> 8) & 0xff) as u8;
    out[2] = ((n2 >>16) & 0xff) as u8;
    out[3] = (n2 >> 24) as u8;
    out[4] = (n1 & 0xff) as u8;
    out[5] = ((n1 >> 8) & 0xff) as u8;
    out[6] = ((n1 >> 16) & 0xff) as u8;
    out[7] = (n1 >> 24) as u8;
}
