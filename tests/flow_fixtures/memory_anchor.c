/* Static-analysis-only fixtures. Never execute the compiled targets.
 * p is valid writable storage; volatile preserves the intended observations,
 * not a concurrency/MMIO model. Unsigned operations avoid overflow UB.
 */
typedef unsigned char u8;
typedef unsigned int u32;
_Static_assert(__CHAR_BIT__ == 8 && sizeof(u8) == 1, "8-bit byte required");
_Static_assert(sizeof(u32) == 4 && sizeof(void *) == 8, "32/64-bit fixture ABI required");
#define KEEP __attribute__((noinline, used))
volatile u8 memory_global;
KEEP u32 memory_before_after(volatile u8 *p) {
    u8 before = p[0];
    p[0] = 0;
    u8 after = p[0];
    return ((u32)before << 8) | after;
}
KEEP u8 memory_alias(volatile u8 *p) {
    volatile u8 *q = p;
    q[0] = 37;
    return p[0];
}
/* For this oracle p == &memory_global. */
KEEP u8 memory_global_roundtrip(volatile u8 *p) {
    memory_global = 41;
    return p[0];
}
/* Oracle selects index == 0; mask keeps every caller within local bounds. */
KEEP u8 memory_stack_roundtrip(u32 index) {
    volatile u8 local[2];
    local[0] = 43;
    local[1] = 47;
    return local[index & 1u];
}
int main(void) { return 0; }
