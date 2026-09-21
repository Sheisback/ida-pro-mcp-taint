/* Compile-time layout evidence only; never link or run this translation unit. */
#include <stddef.h>
#include <limits.h>
#include "../typed_fixture.c"
_Static_assert(sizeof(void *) == 8, "64-bit pointer");
_Static_assert(sizeof(struct Point) == 12, "Point size");
_Static_assert(_Alignof(struct Point) == 4, "Point alignment");
_Static_assert(offsetof(struct Point, x) == 0, "x offset");
_Static_assert(offsetof(struct Point, y) == 4, "y offset");
_Static_assert(offsetof(struct Point, tag) == 8, "tag offset");
_Static_assert(sizeof(((struct Point *)0)->x) == 4, "x width");
_Static_assert(sizeof(((struct Point *)0)->y) == 4, "y width");
_Static_assert(sizeof(((struct Point *)0)->tag) == 1, "tag width");
_Static_assert(CHAR_MIN < 0, "signed char ABI for this oracle");
