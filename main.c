/* main.c --  k.exe <in.exe> [out.exe] */
#include "kp.h"

/* re-read the patched bytes; silent unless something is wrong */
static int self_check(const struct image *img)
{
    static const struct { const char *what; uint64_t va; uint8_t want[2]; int len; } p[] = {
        { "button", 0x1401b6589ull, { 0xe9 }, 1 },
        { "ctor",   0x1401b86d8ull, { 0xe9 }, 1 },
        { "pred",   0x1401bd606ull, { 0xeb }, 1 },
        { "tail",   0x1401b936cull, { 0xb2, 2 }, 2 },
    };
    for (unsigned i = 0; i < sizeof p / sizeof p[0]; i++) {
        uint64_t off = image_va_to_off(img, p[i].va);
        if (off == UINT64_MAX || memcmp(img->data + off, p[i].want, p[i].len) != 0) {
            fprintf(stderr, "bad %s\n", p[i].what);
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: k.exe <in.exe> [out.exe]\n");
        return 2;
    }
    const char *input  = argv[1];
    const char *output = argc > 2 ? argv[2] : input;

    struct image img;
    if (!image_load(&img, input)) {
        fprintf(stderr, "cannot read %s\n", input);
        return 2;
    }
    aes_init_sbox();

    if (!swap_public_key(&img, KP_PUBLIC_KEY) ||
        !inject_self_activation(&img) ||
        !patch_ui(&img) ||
        !patch_ctor_state(&img) ||
        !patch_dialog_state(&img)) {
        fprintf(stderr, "patch failed\n");
        return 1;
    }
    if (!self_check(&img)) return 1;

    if (!image_save(&img, output)) {
        fprintf(stderr, "cannot write %s\n", output);
        return 2;
    }
    printf("%s -> %s (%zu bytes)\n", input, output, img.size);
    return 0;
}
