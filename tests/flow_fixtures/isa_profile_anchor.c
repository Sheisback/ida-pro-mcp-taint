/* Static-analysis-only ISA/ABI fixture. Never execute compiled targets. */
typedef unsigned int u32;

#if defined(_WIN32)
#define KEEP __declspec(dllexport) __attribute__((used, noinline))
#else
#define KEEP __attribute__((used, noinline, visibility("default")))
#endif

volatile u32 isa_profile_sink;

KEEP u32 isa_scalar(u32 left, u32 right) {
    return (left + right) ^ 0x013579bdu;
}

KEEP u32 isa_branch(u32 value, u32 selector) {
    if (selector != 0u) {
        return value + 3u;
    }
    return value ^ 5u;
}

KEEP u32 isa_load(const volatile u32 *slot) {
    return *slot;
}

KEEP void isa_store(volatile u32 *slot, u32 value) {
    *slot = value;
}

KEEP u32 isa_call(u32 value) {
    return isa_scalar(value, 7u);
}

KEEP u32 isa_profile_entry(volatile u32 *slot, u32 selector) {
    u32 value = isa_load(slot);
    value = isa_branch(isa_call(value), selector);
    isa_store(slot, value);
    isa_profile_sink = value;
    return value;
}
