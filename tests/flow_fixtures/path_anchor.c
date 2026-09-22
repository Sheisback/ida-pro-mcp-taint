/* Repository-owned static-analysis input. Build and inspect; never execute. */
typedef unsigned char byte;
static volatile byte sink_left;
static volatile byte sink_right;
__attribute__((noinline)) byte path_anchor(byte x) {
    if (x & 1) sink_left = x;
    else { sink_right = x; sink_right = 7; }
    return x;
}
int main(void) { return 0; }
