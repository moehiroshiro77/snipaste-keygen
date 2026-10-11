/* aes.c -- AES-128 forward only (CTR needs no inverse) */
#include "kp.h"

static uint8_t sbox[256];
static uint32_t round_keys[44];

/* xlatb: AL = [RBX + AL] */
uint8_t aes_sub_byte(uint8_t x)
{
    __asm__("xlatb" : "+a"(x) : "b"(sbox) : "memory");
    return x;
}

/* build the standard S-box: multiplicative inverse in GF(2^8) + affine map */
void aes_init_sbox(void)
{
    for (int value = 0; value < 256; value++) {
        uint8_t inverse = 0;
        for (int candidate = 1; candidate < 256; candidate++) {
            uint8_t product = 0, a = (uint8_t)value, b = (uint8_t)candidate;
            while (b) {
                if (b & 1) product ^= a;
                a = (uint8_t)((a << 1) ^ (a & 0x80 ? 0x1b : 0));
                b >>= 1;
            }
            if (product == 1) { inverse = (uint8_t)candidate; break; }
        }
        uint8_t rotated = (uint8_t)((inverse << 1) | (inverse >> 7));
        uint8_t affine = (uint8_t)(inverse ^ rotated);
        rotated = (uint8_t)((rotated << 1) | (rotated >> 7)); affine ^= rotated;
        rotated = (uint8_t)((rotated << 1) | (rotated >> 7)); affine ^= rotated;
        rotated = (uint8_t)((rotated << 1) | (rotated >> 7)); affine ^= rotated;
        sbox[value] = (uint8_t)(affine ^ 0x63);
    }
}

void aes_expand_key(const uint8_t key[16])
{
    static const uint8_t round_const[10] = {1,2,4,8,16,32,64,128,0x1b,0x36};
    uint32_t w[44];

    for (int i = 0; i < 4; i++) memcpy(&w[i], key + 4 * i, 4);

    for (int i = 4; i < 44; i++) {
        uint32_t t = w[i - 1];
        if ((i & 3) == 0) {
            /* RotWord: little-endian [b0 b1 b2 b3] -> [b1 b2 b3 b0] == ror 8 */
            __asm__("ror $8, %0" : "+r"(t));
            uint8_t *bytes = (uint8_t *)&t;
            for (int j = 0; j < 4; j++) bytes[j] = aes_sub_byte(bytes[j]);
            ((uint8_t *)&t)[0] ^= round_const[(i >> 2) - 1];
        }
        w[i] = w[i - 4] ^ t;
    }
    memcpy(round_keys, w, sizeof w);
}

void aes_encrypt_block(const uint8_t in[16], uint8_t out[16])
{
    uint8_t state[16], scratch[16];

    copy_bytes(state, in, 16);
    for (int i = 0; i < 16; i++) state[i] ^= ((uint8_t *)round_keys)[i];

    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++) state[i] = aes_sub_byte(state[i]);

        copy_bytes(scratch, state, 16);
        for (int c = 0; c < 4; c++)
            for (int q = 0; q < 4; q++)
                state[c * 4 + q] = scratch[((c + q) & 3) * 4 + q];

        if (round != 10) {
            uint8_t mixed[16];
            for (int c = 0; c < 4; c++) {
                uint8_t *col = state + c * 4;
                uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                uint8_t x0 = (uint8_t)((a0 << 1) ^ (a0 & 0x80 ? 0x1b : 0));
                uint8_t x1 = (uint8_t)((a1 << 1) ^ (a1 & 0x80 ? 0x1b : 0));
                uint8_t x2 = (uint8_t)((a2 << 1) ^ (a2 & 0x80 ? 0x1b : 0));
                uint8_t x3 = (uint8_t)((a3 << 1) ^ (a3 & 0x80 ? 0x1b : 0));
                mixed[c * 4 + 0] = x0 ^ (x1 ^ a1) ^ a2 ^ a3;
                mixed[c * 4 + 1] = a0 ^ x1 ^ (x2 ^ a2) ^ a3;
                mixed[c * 4 + 2] = a0 ^ a1 ^ x2 ^ (x3 ^ a3);
                mixed[c * 4 + 3] = (x0 ^ a0) ^ a1 ^ a2 ^ x3;
            }
            copy_bytes(state, mixed, 16);
        }
        for (int i = 0; i < 16; i++) state[i] ^= ((uint8_t *)round_keys)[16 * round + i];
    }
    copy_bytes(out, state, 16);
}
