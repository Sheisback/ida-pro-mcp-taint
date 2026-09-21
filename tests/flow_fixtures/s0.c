/* Repository-owned static-analysis fixtures. Never execute compiled targets. */
#include <stdint.h>
#define KEEP __attribute__((noinline))
KEEP uint32_t s0_scalar(uint32_t x) { return x + UINT32_C(7); }
KEEP uint32_t s0_phi(uint32_t x, uint32_t y, uint32_t c) { uint32_t v; if (c) v = x; else v = y; return v; }
KEEP uint32_t s0_overwrite(uint32_t x) { x = UINT32_C(5); return x; }
KEEP uint32_t s0_partial(uint8_t *p) { p[1] = 0; return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
KEEP uint32_t s0_alias(uint32_t *p, uint32_t x) { uint32_t *q = p; *q = x; return *p; }
KEEP uint32_t s0_merge(uint32_t *p, uint32_t x, uint32_t c) { if (c) *p = x; else *p = UINT32_C(9); return *p; }
KEEP void s0_output(uint32_t *out, uint32_t x) { *out = x + UINT32_C(1); }
KEEP uint32_t s0_unknown(uint32_t *p, void (*effect)(uint32_t *)) { effect(p); return *p; }
int main(void) { return 0; }
