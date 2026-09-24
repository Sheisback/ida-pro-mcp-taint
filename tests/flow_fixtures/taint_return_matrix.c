/* Owned static-only Return/ABI observations. NEVER execute this binary. */
#include <stdint.h>

#define KEEP __attribute__((noinline, used))

KEEP uint8_t return_u8(uint8_t value) { return value; }
KEEP uint16_t return_u16(uint16_t value) { return value; }
KEEP uint32_t return_u32(uint32_t value) { return value; }
KEEP uint64_t return_u64(uint64_t value) { return value; }
KEEP uint32_t return_constant(uint32_t value) {
    (void)value;
    return 7u;
}
KEEP int32_t return_sign_extend(int8_t value) { return (int32_t)value; }
KEEP uint32_t return_zero_extend(uint8_t value) { return (uint32_t)value; }
KEEP uint32_t return_multi(uint32_t value, uint32_t flag) {
    if (flag) return value;
    return 7u;
}
KEEP uint32_t return_unused(uint32_t unused, uint32_t value) {
    (void)unused;
    return value;
}
KEEP uint32_t *return_pointer(uint32_t *value) { return value; }
KEEP void return_void(volatile uint32_t *out, uint32_t value) { *out = value; }
KEEP __attribute__((noreturn)) void return_noreturn(void) { __builtin_trap(); }
KEEP uint32_t return_stack_ninth(
    uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
    uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7,
    uint32_t ninth
) {
    (void)a0; (void)a1; (void)a2; (void)a3;
    (void)a4; (void)a5; (void)a6; (void)a7;
    return ninth;
}

int main(void) { return 0; }
