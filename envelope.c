/* envelope.c -- swap the embedded Ed25519 public key.
 *
 * blob: [0..0x21) ciphertext, [0x21] flag, [0x22..0x2a) ctr seed, [0x2a..0x3a) aes key.
 * stored as 14 dwords at stride 7 plus a trailing imm16.
 */
#include "kp.h"

/* original immediates; used only to locate the structure */
static const uint32_t origin[14] = {
    0x0605d602, 0x6d9aa9ac, 0xa6582f90, 0x4d0a0cbf, 0x7760e0ac, 0xcefc89da, 0x5382e255,
    0xfd1c2a33, 0xebb401bb, 0x2e8af932, 0xc32eac2b, 0x3d010b7a, 0x75d375d6, 0x2ab21f07,
};

static uint64_t find_envelope(const struct image *img)
{
    for (uint64_t off = 0; off + 7 * 14 < img->size; off++) {
        if (read_le(img, off, 4) != origin[0]) continue;
        int matched = 1;
        for (int k = 1; k < 14; k++) {
            if (read_le(img, off + 7 * k, 4) != origin[k]) { matched = 0; break; }
        }
        if (matched) return off;
    }
    return UINT64_MAX;
}

static uint64_t find_trailing_word(const struct image *img, uint64_t envelope_off)
{
    uint64_t start = envelope_off + 7 * 14;
    for (uint64_t off = start; off < start + 32; off++)
        if (read_le(img, off, 2) == 0xf605) return off;
    return UINT64_MAX;
}

/* seed || counter(le). counters are 0,0,1 for a 33-byte payload. */
static void build_keystream(const uint8_t seed[8], const uint8_t key[16], uint8_t stream[33])
{
    aes_expand_key(key);
    for (int block = 0; block < 3; block++) {
        uint64_t counter = block ? (uint64_t)(block - 1) : 0;
        uint8_t input[16], output[16];
        memcpy(input, seed, 8);
        memcpy(input + 8, &counter, 8);
        aes_encrypt_block(input, output);
        memcpy(stream + 16 * block, output, 16);
    }
}

int swap_public_key(struct image *img, const uint8_t pubkey[32])
{
    uint64_t off = find_envelope(img);
    if (off == UINT64_MAX) return 0;

    uint64_t word_off = find_trailing_word(img, off);
    if (word_off == UINT64_MAX) return 0;

    uint8_t blob[58];
    for (int k = 0; k < 14; k++) memcpy(blob + 4 * k, img->data + off + 7 * k, 4);
    memcpy(blob + 56, img->data + word_off, 2);
    if (blob[0x21] != 1) return 0;

    uint8_t keystream[33];
    build_keystream(blob + 0x22, blob + 0x2a, keystream);

    uint8_t plaintext[33];
    memcpy(plaintext, pubkey, 32);
    plaintext[32] = 0;

    for (int i = 0; i < 33; i++) blob[i] = (uint8_t)(plaintext[i] ^ keystream[i]);

    for (int k = 0; k < 14; k++) memcpy(img->data + off + 7 * k, blob + 4 * k, 4);
    memcpy(img->data + word_off, blob + 56, 2);
    return 1;
}
