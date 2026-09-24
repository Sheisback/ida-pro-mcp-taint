/* Repository-owned finite-target examples for STATIC IDA analysis only.
 * NEVER execute the linked binary. These functions are not security sinks.
 */
#include <stdint.h>

#define KEEP __attribute__((noinline, used))
typedef uint32_t (*fn_t)(uint32_t);

KEEP uint32_t finite_identity(uint32_t value) { return value; }
KEEP uint32_t finite_increment(uint32_t value) { return value + 1u; }
KEEP uint32_t finite_constant_seven(uint32_t value) {
    (void)value;
    return 7u;
}
KEEP uint32_t finite_constant_nine(uint32_t value) {
    (void)value;
    return 9u;
}

KEEP uint32_t finite_choose(uint32_t value, uint32_t selector) {
    fn_t target = selector ? finite_identity : finite_increment;
    return target(value);
}

KEEP uint32_t finite_choose_constants(uint32_t value, uint32_t selector) {
    fn_t target = selector ? finite_constant_seven : finite_constant_nine;
    return target(value);
}

KEEP uint32_t finite_choose_unknown(uint32_t value, uint32_t selector, fn_t other) {
    fn_t target = selector ? finite_identity : other;
    return target(value);
}

int main(void) { return 0; }
