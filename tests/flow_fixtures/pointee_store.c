/* Static-only fixture. Never execute this target; pointers are caller assumptions. */
#include <stdint.h>
#include <stddef.h>

typedef struct Request { volatile uint8_t *buffer; } Request;
typedef void (*Callback)(void);
typedef struct Owner { uint64_t pad; Callback slots[16]; } Owner;
_Static_assert(offsetof(Owner, slots[14]) == 120, "fixture slot offset");

__attribute__((noinline)) uint64_t pointee_partial_clear(Request *request) {
    volatile uint8_t *buffer = request->buffer;
    *(volatile uint32_t *)buffer = 0;
    return *(volatile uint64_t *)buffer;
}
__attribute__((noinline)) void callback_target(void) { }
__attribute__((noinline)) void register_callback(Owner *owner) {
    owner->slots[14] = callback_target;
}
__attribute__((noinline)) void register_truncated(Owner *owner) {
    owner->slots[14] = (Callback)(uintptr_t)(uint32_t)(uintptr_t)callback_target;
}
__attribute__((noinline)) void register_changed(Owner *owner) {
    owner->slots[14] = (Callback)((uintptr_t)callback_target + 1);
}
int main(void) { return 0; }
