/* kp.h -- types and entry points */
#ifndef KP_H
#define KP_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pub.inc"
#include "tok.inc"

struct section {
    uint32_t va;              /* RVA */
    uint32_t virtual_size;
    uint32_t raw_ptr;         /* file offset */
    uint32_t raw_size;
};

struct image {
    uint8_t *data;
    size_t   size;            /* current file length */
    size_t   capacity;
    int      section_count;
    struct section sections[32];
    uint32_t file_align;
    uint32_t section_align;
};

int      image_load(struct image *img, const char *path);
int      image_save(const struct image *img, const char *path);
void     image_parse(struct image *img);
uint64_t image_va_to_off(const struct image *img, uint64_t va);
int      image_find_section(const struct image *img, const char *name);
int      image_add_section(struct image *img, const char *name, uint32_t rva,
                           const uint8_t *payload, uint32_t len, uint32_t chars);
uint64_t read_le(const struct image *img, uint64_t off, int bytes);
void     write_le(struct image *img, uint64_t off, uint64_t value, int bytes);
int      image_reserve(struct image *img, size_t need);
void     copy_bytes(void *dst, const void *src, size_t n);

void    aes_init_sbox(void);
void    aes_expand_key(const uint8_t key[16]);
void    aes_encrypt_block(const uint8_t in[16], uint8_t out[16]);
uint8_t aes_sub_byte(uint8_t x);

int swap_public_key(struct image *img, const uint8_t pubkey[32]);
int inject_self_activation(struct image *img);
int patch_ui(struct image *img);
int patch_ctor_state(struct image *img);
int patch_dialog_state(struct image *img);

uint32_t build_activation_stub(uint8_t *dst, size_t capacity, uint64_t stub_va,
                               uint32_t token_len);

#endif /* KP_H */
