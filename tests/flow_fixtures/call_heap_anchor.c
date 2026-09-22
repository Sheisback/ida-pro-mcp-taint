/* Static-analysis-only call and heap fixtures. Never execute this target.
 *
 * The H01/H04 helpers intentionally retain post-free reads so a binary
 * analysis can observe lifetime boundaries. Their runtime behavior is outside
 * the fixture contract. Volatile accesses preserve observations at -O0; they
 * are not a concurrency or MMIO model.
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long usize;

_Static_assert(__CHAR_BIT__ == 8 && sizeof(u8) == 1, "8-bit byte required");
_Static_assert(sizeof(u32) == 4 && sizeof(void *) == 8, "32/64-bit fixture ABI required");

#define KEEP __attribute__((noinline, used))

typedef u32 (*call_value_fn)(u32);
typedef void (*call_heap_effect_fn)(volatile u8 *);

extern void *malloc(usize size);
extern void free(void *pointer);

volatile u32 call_global_value;
volatile u8 *call_escaped_heap;

KEEP u32 call_identity(u32 value) { return value; }

KEEP void call_copy(volatile u8 *destination, const volatile u8 *source, usize length) {
    for (usize index = 0; index < length; ++index) {
        destination[index] = source[index];
    }
}

KEEP void call_fill(volatile u8 *destination, u8 value, usize length) {
    for (usize index = 0; index < length; ++index) {
        destination[index] = value;
    }
}

KEEP void call_output(volatile u32 *output, u32 value) { output[0] = value; }

KEEP void call_output_user(volatile u32 *output, u32 value) {
    call_output(output, value);
}

KEEP u32 call_global(u32 value) {
    call_global_value = value;
    return call_global_value;
}

KEEP void *call_alloc(usize size) { return malloc(size); }

KEEP void call_free(void *pointer) { free(pointer); }

KEEP u32 call_context_left(u32 value) { return call_identity(value) + 1u; }

KEEP u32 call_context_right(u32 value) { return call_identity(value) + 2u; }

KEEP u32 call_recursive(u32 value, u32 depth) {
    if (depth == 0u) {
        return call_identity(value);
    }
    return call_recursive(value + 1u, depth - 1u);
}

KEEP u32 call_candidate_increment(u32 value) { return value + 1u; }

KEEP u32 call_indirect(u32 value, u32 selector, call_value_fn unknown_candidate) {
    call_value_fn selected = unknown_candidate;
    if (selector == 0u) {
        selected = call_identity;
    } else if (selector == 1u) {
        selected = call_candidate_increment;
    }
    return selected(value);
}

KEEP u32 call_heap_h01(u8 value) {
    volatile u8 *pointer = (volatile u8 *)call_alloc(1u);
    if (pointer == (void *)0) {
        return 0u;
    }
    pointer[0] = value;
    call_free((void *)pointer);
    return pointer[0];
}

KEEP u32 call_heap_h02(u8 value) {
    volatile u8 *left = (volatile u8 *)call_alloc(1u);
    volatile u8 *right = (volatile u8 *)call_alloc(1u);
    if (left == (void *)0 || right == (void *)0) {
        call_free((void *)left);
        call_free((void *)right);
        return 0u;
    }
    left[0] = 17u;
    right[0] = value;
    call_free((void *)left);
    value = right[0];
    call_free((void *)right);
    return value;
}

KEEP u32 call_heap_h03(u8 value, call_heap_effect_fn unknown_effect) {
    volatile u8 *pointer = (volatile u8 *)call_alloc(1u);
    if (pointer == (void *)0) {
        return 0u;
    }
    pointer[0] = value;
    call_escaped_heap = pointer;
    unknown_effect(pointer);
    return pointer[0];
}

KEEP u32 call_heap_h04(u8 value, u32 may_free) {
    volatile u8 *pointer = (volatile u8 *)call_alloc(1u);
    if (pointer == (void *)0) {
        return 0u;
    }
    pointer[0] = value;
    if (may_free != 0u) {
        call_free((void *)pointer);
    }
    return pointer[0];
}

int main(void) { return 0; }
