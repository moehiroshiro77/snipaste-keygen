/* dialog.c -- open the unlock dialog in the activated state.
 *
 * 4  ctor cave: replay updateHtmlStyle, then render state 5
 * 5a predicate jne -> jmp (status 0x0C would return false and never switch page)
 * 5b jump-table case 6 -> cave passing state 5 (timer would switch back)
 * 5c ctor tail xor edx,edx -> mov dl,2 (removes the few-second delay)
 */
#include "kp.h"

int patch_ctor_state(struct image *img)
{
    int index = image_find_section(img, ".snip");
    if (index < 0) return 0;
    uint64_t section_va = 0x140000000ull + img->sections[index].va;

    uint64_t cave_va = section_va + 0x700;
    uint8_t *cave = img->data + image_va_to_off(img, cave_va);
    uint32_t at = 0;

    cave[at++] = 0xe8;                                    /* call updateHtmlStyle */
    int32_t d1 = (int32_t)(0x1401bc150ull - (cave_va + at + 4));
    memcpy(cave + at, &d1, 4); at += 4;

    memcpy(cave + at, "\x48\x8b\xce", 3); at += 3;        /* mov rcx, rsi */
    cave[at++] = 0xba;                                    /* mov edx, 5 */
    uint32_t state = 5;
    memcpy(cave + at, &state, 4); at += 4;

    cave[at++] = 0xe8;                                    /* call page renderer */
    int32_t d2 = (int32_t)(0x1401be190ull - (cave_va + at + 4));
    memcpy(cave + at, &d2, 4); at += 4;

    cave[at++] = 0xe9;                                    /* jmp back */
    int32_t d3 = (int32_t)(0x1401b86ddull - (cave_va + at + 4));
    memcpy(cave + at, &d3, 4);

    uint64_t site = image_va_to_off(img, 0x1401b86d8ull);
    img->data[site] = 0xe9;
    int32_t rel = (int32_t)(cave_va - (0x1401b86d8ull + 5));
    memcpy(img->data + site + 1, &rel, 4);
    return 1;
}

int patch_dialog_state(struct image *img)
{
    int index = image_find_section(img, ".snip");
    if (index < 0) return 0;
    uint64_t section_va = 0x140000000ull + img->sections[index].va;

    /* 5a */
    uint64_t predicate = image_va_to_off(img, 0x1401bd606ull);
    if (predicate == UINT64_MAX) return 0;
    if (read_le(img, predicate, 2) != 0x0775) return 0;
    img->data[predicate] = 0xeb;

    /* 5b */
    uint64_t cave_va = section_va + 0x740;
    uint8_t *cave = img->data + image_va_to_off(img, cave_va);
    uint32_t at = 0;
    cave[at++] = 0xba;                                    /* mov edx, 5 */
    uint32_t state = 5;
    memcpy(cave + at, &state, 4); at += 4;
    cave[at++] = 0xe9;                                    /* jmp page renderer */
    int32_t d = (int32_t)(0x1401be190ull - (cave_va + at + 4));
    memcpy(cave + at, &d, 4);

    uint64_t table_entry = image_va_to_off(img, 0x140333458ull + 6 * 4);
    uint32_t offset_from_base = (uint32_t)(cave_va - 0x140000000ull);
    memcpy(img->data + table_entry, &offset_from_base, 4);

    /* 5c */
    uint64_t reset = image_va_to_off(img, 0x1401b936cull);
    if (reset == UINT64_MAX) return 0;
    if (read_le(img, reset, 2) != 0xd233) return 0;
    img->data[reset]     = 0xb2;                          /* mov dl, 2 */
    img->data[reset + 1] = 2;
    return 1;
}
