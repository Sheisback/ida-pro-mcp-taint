/* Static-analysis-only fixture. Never execute compiled targets. */
typedef unsigned int u32;
struct Pair { u32 x; u32 y; };
__attribute__((noinline)) u32 p0_helper(u32 x) { return x + 7u; }
__attribute__((noinline)) unsigned long long p0_anchor(struct Pair *p, u32 flag) {
    u32 x = p->x;
    if (flag) x = p0_helper(x);
    else x ^= p->y;
    p->x = x;
    return (unsigned long long)x;
}
int main(void) { struct Pair p = {1, 2}; return (int)p0_anchor(&p, 1); }
