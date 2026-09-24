/* Benign, repository-owned static-analysis examples. NEVER execute the targets.
 * The first argument is the selected source; a dedicated volatile write records
 * each result for static observation (native terminal returns are not exposed).
 * These are not security sinks. Volatile preserves memory accesses across
 * optimization. The observer is instrumentation, not an unmodified return test.
 */
#include <stdint.h>
#define KEEP __attribute__((noinline, used))
volatile uintptr_t taint_observation;
#define RETURN(v) do { __typeof__(v) result = (v); taint_observation = result; return result; } while (0)

typedef struct { uint32_t a, b; } Pair;
typedef union { uint32_t word; uint8_t bytes[4]; } Word;
static volatile uint32_t global_word;

KEEP uint32_t taint_identity(uint32_t x) { RETURN(x); }
KEEP uintptr_t taint_pointer_identity(uintptr_t x) { RETURN(x); }
KEEP uint32_t taint_arithmetic(uint32_t x) { RETURN((x + 7u) ^ 0x55u); }
KEEP uint32_t taint_overwrite(uint32_t x) { x = 7; RETURN(x); }
KEEP uint32_t taint_and_zero(uint32_t x) { RETURN(x & 0u); }
KEEP uint32_t taint_multiply_zero(uint32_t x) { RETURN(x * 0u); }
KEEP uint32_t taint_xor_self(uint32_t x) { RETURN(x ^ x); }
KEEP uint32_t taint_subtract_self(uint32_t x) { RETURN(x - x); }
KEEP uint32_t taint_independent(uint32_t x, uint32_t y) { (void)x; RETURN(y + 1u); }
KEEP uint32_t taint_select_value(uint32_t x, uint32_t flag) { RETURN(flag ? x : 7u); }
KEEP uint32_t taint_branch_constant(uint32_t x) {
    volatile uint32_t y;
    if (x) y = 3; else y = 7;
    RETURN(y);
}
KEEP uint32_t taint_branch_same(uint32_t x) {
    uint32_t y;
    if (x) y = 7; else y = 7;
    RETURN(y);
}
KEEP uint32_t taint_loop(uint32_t x, uint32_t n) {
    uint32_t y = 0;
    for (uint32_t i = 0; i < (n & 7u); ++i) y += x;
    RETURN(y);
}
KEEP uint32_t taint_stack_roundtrip(uint32_t x) { volatile uint32_t y = x; RETURN(y); }
KEEP uint32_t taint_stack_overwrite(uint32_t x) { volatile uint32_t y = x; y = 7; RETURN(y); }
KEEP uint32_t taint_struct_other(uint32_t x) { volatile Pair p = {x, 7}; RETURN(p.b); }
KEEP uint32_t taint_struct_same(uint32_t x) { volatile Pair p = {x, 7}; RETURN(p.a); }
KEEP uint32_t taint_array_constant(uint32_t x) { volatile uint32_t a[2] = {x, 7}; RETURN(a[0]); }
KEEP uint32_t taint_array_index(uint32_t x, uint32_t n) { volatile uint32_t a[2] = {x, 7}; RETURN(a[n & 1u]); }
KEEP uint32_t taint_partial_clear(uint32_t x) { volatile Word w; w.word = x; w.bytes[0] = 0; RETURN(w.word); }
KEEP uint32_t taint_full_byte_clear(uint32_t x) {
    volatile Word w; w.word = x;
    w.bytes[0] = 0; w.bytes[1] = 0; w.bytes[2] = 0; w.bytes[3] = 0;
    RETURN(w.word);
}
KEEP uint32_t taint_global_roundtrip(uint32_t x) { global_word = x; RETURN(global_word); }
KEEP uint32_t taint_global_overwrite(uint32_t x) { global_word = x; global_word = 7; RETURN(global_word); }
KEEP uint32_t taint_call_identity(uint32_t x) { RETURN(taint_identity(x)); }
KEEP uint32_t taint_call_indirect(uint32_t x, uint32_t (*fn)(uint32_t)) { RETURN(fn(x)); }
KEEP uint32_t taint_pointer_only(const volatile uint32_t *p) { RETURN(*p); }
KEEP uint32_t taint_load_before_store(uint32_t x, volatile uint32_t *p) { uint32_t old = *p; *p = x; RETURN(old); }
KEEP uint32_t taint_store_then_load(uint32_t x, volatile uint32_t *p) { *p = x; RETURN(*p); }
int main(void) { return 0; }
