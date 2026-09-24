/* Benign static-only companion to taint_scenarios.c; never execute it. */
#include <stdint.h>
#define KEEP __attribute__((noinline, used))

KEEP uint32_t taint_static_seven(void) { return 7u; }
KEEP uint32_t taint_call_static_seven(uint32_t x) {
    (void)x;
    return taint_static_seven();
}
KEEP uint32_t taint_call_static_seven_preserve(uint32_t x) {
    volatile uint32_t saved = x;
    (void)taint_static_seven();
    return saved;
}
KEEP void taint_write_output(uint32_t x, volatile uint32_t *out) {
    *out = x;
}
KEEP uint32_t taint_call_write_output(uint32_t x) {
    volatile uint32_t out = 7u;
    taint_write_output(x, &out);
    return out;
}
KEEP uint32_t taint_low32_roundtrip(uint64_t x) {
    volatile uint64_t saved = x;
    return (uint32_t)saved;
}
KEEP uint32_t taint_high32_roundtrip(uint64_t x) {
    volatile uint64_t saved = x;
    return (uint32_t)(saved >> 32);
}
KEEP void taint_write_u64(volatile uint64_t *out, uint64_t x) {
    *out = x;
}
KEEP uint32_t taint_bit_output_low(uint64_t x) {
    volatile uint64_t out = 0;
    taint_write_u64(&out, x);
    return (uint32_t)out;
}
KEEP uint32_t taint_bit_output_high(uint64_t x) {
    volatile uint64_t out = 0;
    taint_write_u64(&out, x);
    return (uint32_t)(out >> 32);
}
