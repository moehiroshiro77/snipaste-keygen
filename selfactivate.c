/* selfactivate.c -- add the .snip section and hook the publish site */
#include "kp.h"

int inject_self_activation(struct image *img)
{
    uint64_t site = image_va_to_off(img, 0x140252387ull);
    if (site == UINT64_MAX) return 0;
    if (memcmp(img->data + site, "\x48\x8b\x05\xfa\x4e\x41\x00", 7) != 0) return 0;

    /* new section rva: after the highest section end, aligned */
    uint64_t highest_end = 0;
    for (int i = 0; i < img->section_count; i++) {
        uint64_t end = (uint64_t)img->sections[i].va + img->sections[i].virtual_size;
        if (end > highest_end) highest_end = end;
    }
    uint64_t rva = (highest_end + img->section_align - 1) / img->section_align * img->section_align;
    uint64_t section_va = 0x140000000ull + rva;

    uint8_t payload[0x320];
    memset(payload, 0, sizeof payload);

    if (build_activation_stub(payload, 0x98, section_va, sizeof KP_LICENSE_TOKEN) == 0) return 0;
    memcpy(payload + 0x100, KP_LICENSE_TOKEN, sizeof KP_LICENSE_TOKEN);

    if (!image_add_section(img, ".snip", (uint32_t)rva, payload,
                           (uint32_t)sizeof payload, 0xe0000060u))
        return 0;

    /* replace the 5-byte mov with jmp; pad the rest with nop */
    site = image_va_to_off(img, 0x140252387ull);
    if (site == UINT64_MAX) return 0;
    img->data[site] = 0xe9;
    int32_t rel32 = (int32_t)(section_va - (0x140252387ull + 5));
    memcpy(img->data + site + 1, &rel32, 4);
    img->data[site + 5] = 0x90;
    img->data[site + 6] = 0x90;
    return 1;
}
