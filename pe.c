/* pe.c -- minimal PE: section table, VA<->offset, append section */
#include "kp.h"

/* rep movsb: bulk copy for small fixed sizes on the hot path */
void copy_bytes(void *dst, const void *src, size_t n)
{
    __asm__ volatile("rep movsb" : "+D"(dst), "+S"(src), "+c"(n) : : "memory");
}

uint64_t read_le(const struct image *img, uint64_t off, int bytes)
{
    uint64_t value = 0;
    if (off + bytes > img->size) return 0;
    memcpy(&value, img->data + off, bytes);
    return value;
}

void write_le(struct image *img, uint64_t off, uint64_t value, int bytes)
{
    if (off + bytes > img->size) return;
    memcpy(img->data + off, &value, bytes);
}

/* grow buffer so that [0, need) is valid and zero-filled */
int image_reserve(struct image *img, size_t need)
{
    if (need <= img->capacity) {
        if (need > img->size) {
            memset(img->data + img->size, 0, need - img->size);
            img->size = need;
        }
        return 1;
    }
    size_t cap = img->capacity ? img->capacity : (1u << 20);
    while (cap < need) cap *= 2;
    uint8_t *grown = realloc(img->data, cap);
    if (!grown) return 0;
    memset(grown + img->capacity, 0, cap - img->capacity);
    img->data = grown;
    img->capacity = cap;
    if (need > img->size) {
        memset(img->data + img->size, 0, need - img->size);
        img->size = need;
    }
    return 1;
}

int image_load(struct image *img, const char *path)
{
    memset(img, 0, sizeof *img);
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 0; }
    long length = ftell(fp);
    if (length <= 0) { fclose(fp); return 0; }
    rewind(fp);

    img->capacity = (size_t)length + (1u << 20);
    img->data = calloc(1, img->capacity);
    if (!img->data) { fclose(fp); return 0; }
    img->size = (size_t)length;
    if (fread(img->data, 1, img->size, fp) != img->size) { fclose(fp); return 0; }
    fclose(fp);
    image_parse(img);
    return 1;
}

int image_save(const struct image *img, const char *path)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    size_t written = fwrite(img->data, 1, img->size, fp);
    fclose(fp);
    return written == img->size;
}

/* e_lfanew is 0x128 in this build, not the usual 0x3c */
static uint32_t pe_offset(const struct image *img)
{
    return (uint32_t)read_le(img, 0x3c, 4);
}

static uint32_t optional_header_offset(const struct image *img)
{
    return pe_offset(img) + 24;
}

static uint32_t section_table_offset(const struct image *img)
{
    return optional_header_offset(img) + (uint32_t)read_le(img, pe_offset(img) + 20, 2);
}

void image_parse(struct image *img)
{
    uint32_t opt = optional_header_offset(img);
    img->section_align = (uint32_t)read_le(img, opt + 32, 4);
    img->file_align    = (uint32_t)read_le(img, opt + 36, 4);
    img->section_count = (int)read_le(img, pe_offset(img) + 6, 2);
    if (img->section_count > 32) img->section_count = 32;

    uint32_t table = section_table_offset(img);
    for (int i = 0; i < img->section_count; i++) {
        uint32_t hdr = table + (uint32_t)i * 40;
        struct section *s = &img->sections[i];
        s->virtual_size = (uint32_t)read_le(img, hdr + 8, 4);
        s->va           = (uint32_t)read_le(img, hdr + 12, 4);
        s->raw_size     = (uint32_t)read_le(img, hdr + 16, 4);
        s->raw_ptr      = (uint32_t)read_le(img, hdr + 20, 4);
    }
}

uint64_t image_va_to_off(const struct image *img, uint64_t va)
{
    uint64_t rva = va - 0x140000000ull;
    for (int i = 0; i < img->section_count; i++) {
        const struct section *s = &img->sections[i];
        uint64_t span = s->virtual_size > s->raw_size ? s->virtual_size : s->raw_size;
        if (rva >= s->va && rva < s->va + span)
            return s->raw_ptr + (rva - s->va);
    }
    return UINT64_MAX;
}

/* section name lives in the section header, not at PointerToRawData */
int image_find_section(const struct image *img, const char *name)
{
    uint32_t table = section_table_offset(img);
    for (int i = 0; i < img->section_count; i++)
        if (memcmp(img->data + table + (uint32_t)i * 40, name, 5) == 0)
            return i;
    return -1;
}

/* append a section: align file tail, write header, bump count and SizeOfImage */
int image_add_section(struct image *img, const char *name, uint32_t rva,
                      const uint8_t *payload, uint32_t len, uint32_t chars)
{
    uint32_t pe = pe_offset(img);
    uint32_t opt = optional_header_offset(img);
    uint32_t table = section_table_offset(img);
    uint32_t file_align = (uint32_t)read_le(img, opt + 36, 4);
    uint32_t sect_align = (uint32_t)read_le(img, opt + 32, 4);
    if (file_align == 0 || sect_align == 0) return 0;

    uint64_t raw_start = (img->size + file_align - 1) / file_align * file_align;
    uint64_t padded = (uint64_t)len + (file_align - len % file_align) % file_align;
    if (!image_reserve(img, raw_start + padded)) return 0;
    memcpy(img->data + raw_start, payload, len);

    uint8_t header[40];
    memset(header, 0, sizeof header);
    memcpy(header, name, strlen(name));
    memcpy(header + 8,  &len, 4);
    memcpy(header + 12, &rva, 4);
    memcpy(header + 16, &len, 4);
    uint32_t raw32 = (uint32_t)raw_start;
    memcpy(header + 20, &raw32, 4);
    memcpy(header + 36, &chars, 4);
    memcpy(img->data + table + (uint32_t)img->section_count * 40, header, 40);

    uint16_t count = (uint16_t)(img->section_count + 1);
    memcpy(img->data + pe + 6, &count, 2);

    uint32_t image_end = rva + (len + sect_align - 1) / sect_align * sect_align;
    memcpy(img->data + opt + 56, &image_end, 4);

    image_parse(img);
    return 1;
}
