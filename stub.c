/* stub.c -- byte emitter for the activation stub.
 *
 * Replays the displaced `mov rax,[singleton]`, stashes the manager, wraps the
 * token into a static QByteArray, calls the install function, restores
 * rax/rcx/rdx/r8-r11, jumps back. Busy flag guards reentry.
 */
#include "kp.h"

struct stub_builder {
    uint8_t code[256];
    uint32_t length;
    struct { uint32_t at; uint64_t target; uint8_t span; } fixups[64];
    int fixup_count;
    uint64_t base_va;
};

static void emit(struct stub_builder *b, const void *bytes, size_t n)
{
    memcpy(b->code + b->length, bytes, n);
    b->length += (uint32_t)n;
}

/* trailing = immediate bytes that follow the displacement in the same insn */
static void emit_rip(struct stub_builder *b, uint64_t target_va, uint8_t trailing)
{
    b->fixups[b->fixup_count].at = b->length;
    b->fixups[b->fixup_count].target = target_va;
    b->fixups[b->fixup_count].span = (uint8_t)(4 + trailing);
    b->fixup_count++;

    uint32_t zero = 0;
    emit(b, &zero, 4);
}

static void resolve(struct stub_builder *b)
{
    for (int i = 0; i < b->fixup_count; i++) {
        int64_t delta = (int64_t)b->fixups[i].target
                      - (int64_t)(b->base_va + b->fixups[i].at + b->fixups[i].span);
        int32_t rel32 = (int32_t)delta;
        memcpy(b->code + b->fixups[i].at, &rel32, 4);
    }
}

uint32_t build_activation_stub(uint8_t *dst, size_t capacity, uint64_t stub_va,
                               uint32_t token_len)
{
    const uint64_t busy = stub_va + 0x300;
    const uint64_t token = stub_va + 0x100;
    const uint64_t qba = stub_va + 0xa0;
    const uint64_t slot = stub_va + 0x98;

    struct stub_builder b;
    memset(&b, 0, sizeof b);
    b.base_va = stub_va;

    /* if (busy) goto done; busy = 1; */
    emit(&b, "\x80\x3d", 2);
    emit_rip(&b, busy, 1);
    emit(&b, "\x00", 1);

    uint32_t jump_to_done = b.length;
    emit(&b, "\x75\x00", 2);

    emit(&b, "\xc6\x05", 2);
    emit_rip(&b, busy, 1);
    emit(&b, "\x01", 1);

    static const uint8_t push_regs[] = {
        0x50, 0x51, 0x52,                                 /* rax rcx rdx */
        0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53    /* r8 r9 r10 r11 */
    };
    emit(&b, push_regs, sizeof push_regs);
    emit(&b, "\x48\x83\xec\x08", 4);                      /* 7 pushes -> rsp%16==8 */

    /* replay the displaced load, stash the manager */
    emit(&b, "\x48\x8b\x05", 3);
    emit_rip(&b, 0x140667288ull, 0);
    emit(&b, "\x48\x89\x05", 3);
    emit_rip(&b, slot, 0);
    emit(&b, "\x48\x8b\x0d", 3);
    emit_rip(&b, slot, 0);

    /* static QByteArray { d = nullptr, ptr = &token, size = token_len } */
    emit(&b, "\x48\x8d\x05", 3);
    emit_rip(&b, token, 0);
    emit(&b, "\x48\x89\x05", 3);
    emit_rip(&b, qba + 8, 0);
    emit(&b, "\x48\xc7\x05", 3);
    emit_rip(&b, qba + 0x10, 4);
    emit(&b, &token_len, 4);
    emit(&b, "\x48\xc7\x05", 3);
    emit_rip(&b, qba, 4);
    uint32_t zero32 = 0;
    emit(&b, &zero32, 4);

    /* call install(manager, &QByteArray) */
    emit(&b, "\x48\x8d\x15", 3);
    emit_rip(&b, qba, 0);
    emit(&b, "\xe8", 1);
    emit_rip(&b, 0x14024f160ull, 0);

    emit(&b, "\x48\x83\xc4\x08", 4);
    static const uint8_t pop_regs[] = {
        0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58,   /* r11 r10 r9 r8 */
        0x5a, 0x59, 0x58                                  /* rdx rcx rax */
    };
    emit(&b, pop_regs, sizeof pop_regs);
    emit(&b, "\xc6\x05", 2);
    emit_rip(&b, busy, 1);
    emit(&b, "\x00", 1);

    /* done: reload the singleton (rax is the return value), jump back */
    uint32_t done = b.length;
    emit(&b, "\x48\x8b\x05", 3);
    emit_rip(&b, 0x140667288ull, 0);
    emit(&b, "\xe9", 1);
    emit_rip(&b, 0x14025238eull, 0);

    resolve(&b);
    b.code[jump_to_done + 1] = (uint8_t)((done - (jump_to_done + 2)) & 0xff);

    if (b.length > capacity) return 0;
    memcpy(dst, b.code, b.length);
    return b.length;
}
