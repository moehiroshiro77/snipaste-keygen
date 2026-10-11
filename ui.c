/* ui.c -- grow .snip, grey out the deactivate button, About credit */
#include "kp.h"

/* credit html */
static const unsigned char credit[] = {
    0x3c,0x70,0x3e,0x3c,0x62,0x3e,0x43,0x72,0x61,0x63,0x6b,0x65,
    0x64,0x20,0x62,0x79,0x20,0x6d,0x6f,0x65,0x68,0x69,0x72,0x6f,
    0x73,0x68,0x69,0x72,0x6f,0x37,0x37,0x3c,0x2f,0x62,0x3e,0x3c,
    0x2f,0x70,0x3e,
};

/* grow .snip; only when it is the last section in the file */
static int grow_section(struct image *img, int index)
{
    uint64_t tail = 0;
    for (int i = 0; i < img->section_count; i++) {
        uint64_t end = (uint64_t)img->sections[i].raw_ptr + img->sections[i].raw_size;
        if (end > tail) tail = end;
    }
    const struct section *snip = &img->sections[index];
    if ((uint64_t)snip->raw_ptr + snip->raw_size < tail) return 0;

    uint64_t end = image_va_to_off(img, 0x140000000ull + snip->va) + 0x800;
    if (!image_reserve(img, end)) return 0;

    uint32_t pe = (uint32_t)read_le(img, 0x3c, 4);
    uint32_t table = pe + 24 + (uint32_t)read_le(img, pe + 20, 2);
    uint32_t size = 0x800;
    memcpy(img->data + table + (uint32_t)index * 40 + 8,  &size, 4);   /* VirtualSize */
    memcpy(img->data + table + (uint32_t)index * 40 + 16, &size, 4);   /* SizeOfRawData */
    image_parse(img);
    return 1;
}

/* hook the store that puts the button into [rsi+0x228]; cave calls setDisabled(true).
 * setDisabled (not a flipped branch) because Qt marks the widget WA_ForceDisabled,
 * which a later setEnabled(true) on a parent cannot undo. */
static int patch_deactivate_button(struct image *img, uint64_t section_va)
{
    uint64_t hook = image_va_to_off(img, 0x1401b6589ull);
    if (hook == UINT64_MAX) return 0;
    if (memcmp(img->data + hook, "\x48\x89\x9e\x28\x02\x00\x00", 7) != 0) return 0;

    uint64_t cave_va = section_va + 0x400;
    uint8_t *cave = img->data + image_va_to_off(img, cave_va);
    uint32_t at = 0;

    memcpy(cave + at, "\x48\x89\x9e\x28\x02\x00\x00", 7); at += 7;   /* replay the store */
    memcpy(cave + at, "\x48\x89\xd9", 3); at += 3;                   /* mov rcx, rbx */
    memcpy(cave + at, "\xba\x01\x00\x00\x00", 5); at += 5;           /* mov edx, 1 */
    cave[at++] = 0xff; cave[at++] = 0x15;                            /* call [rip+d] */
    int32_t disp = (int32_t)(0x14041d6c0ull - (cave_va + at + 4));
    memcpy(cave + at, &disp, 4); at += 4;
    cave[at++] = 0xe9;                                               /* jmp back */
    int32_t rel = (int32_t)(0x1401b6590ull - (cave_va + at + 4));
    memcpy(cave + at, &rel, 4);

    img->data[hook] = 0xe9;
    int32_t hook_rel = (int32_t)(cave_va - (0x1401b6589ull + 5));
    memcpy(img->data + hook + 1, &hook_rel, 4);
    img->data[hook + 5] = 0x90;
    img->data[hook + 6] = 0x90;
    return 1;
}

/* copy the About html template into .snip, insert the credit, repoint the lea.
 * plain <p> only: the template's own "-qt-paragraph-type:empty" makes Qt drop
 * the paragraph as an empty block. */
static int patch_about_credit(struct image *img, uint64_t section_va)
{
    uint64_t template_off = image_va_to_off(img, 0x140539680ull);
    if (template_off == UINT64_MAX) return 0;

    uint32_t template_len = 0;
    while (template_len < 0x400 && img->data[template_off + template_len]) template_len++;
    if (template_len == 0) return 0;

    uint32_t credit_len = (uint32_t)sizeof credit;

    /* insert after the first </b></p> (the app-name line) */
    uint32_t insert_at = template_len;
    for (uint32_t i = 0; i + 8 <= template_len; i++) {
        if (memcmp(img->data + template_off + i, "</b></p>", 8) == 0) { insert_at = i + 8; break; }
    }

    uint8_t copy[1024];
    if (template_len + credit_len + 1 > sizeof copy) return 0;
    memcpy(copy, img->data + template_off, template_len);
    memmove(copy + insert_at + credit_len, copy + insert_at, template_len - insert_at);
    memcpy(copy + insert_at, credit, credit_len);
    uint32_t total = template_len + credit_len;
    copy[total++] = 0;

    uint64_t target_va = section_va + 0x500;
    memcpy(img->data + image_va_to_off(img, target_va), copy, total);

    uint64_t lea_disp_off = image_va_to_off(img, 0x140170a70ull + 3);
    int32_t disp = (int32_t)(target_va - (0x140170a70ull + 7));
    memcpy(img->data + lea_disp_off, &disp, 4);
    return 1;
}

int patch_ui(struct image *img)
{
    int index = image_find_section(img, ".snip");
    if (index < 0) return 0;
    uint64_t section_va = 0x140000000ull + img->sections[index].va;

    if (!grow_section(img, index)) return 0;
    if (!patch_deactivate_button(img, section_va)) return 0;
    if (!patch_about_credit(img, section_va)) return 0;
    return 1;
}
