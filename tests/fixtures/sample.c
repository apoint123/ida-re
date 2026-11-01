#include <stdio.h>

int add(int a, int b) { return a + b; }

int compute(int x) { return add(x, 7) * 4; }

int main(void) {
    printf("probe result: %d\n", compute(5));
    return 0;
}
