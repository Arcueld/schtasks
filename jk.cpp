#include <stdio.h>
#include <windows.h>
#include "helper.h"

extern myNtAllocateVirtualMemory NtAllocateVirtualMemory;
extern PNtFreeVirtualMemory NtFreeVirtualMemory;

int is_prime(int n) {
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    for (int i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return 0;
    }
    return 1;
}
int jk(int num) {
    PVOID arr = NULL;
    SIZE_T payload_len = num * sizeof(int);

    NtAllocateVirtualMemory(GetCurrentProcess(), &arr, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    int* int_arr = (int*)arr;

    for (int i = 0; i < num; i++) {
        int_arr[i] = i;
    }
    for (int i = 0; i < num; i++) {
        for (int j = 0; j < num; j++) {
            int_arr[i] += int_arr[j];
        }
    }
    NtFreeVirtualMemory(GetCurrentProcess, &arr, (PULONG) & payload_len, MEM_RELEASE);
    int b = 1155433;
    return b;
}
int count_factors(int n) {
    int count = 0;
    for (int i = 1; i <= n; ++i) {
        if (n % i == 0) {
            count++;
        }
    }
    return count;
}
int Sleep4() {
    int num = 5000;
    int prime_count = 0;
    for (int i = 1; i <= num; ++i) {
        if (is_prime(i)) {
            prime_count++;
        }
    }

    int factor_count = 0;
    for (int i = 1; i <= num; ++i) {
        factor_count += count_factors(i);
    }
    return factor_count;
}
void doCalc() {
    jk(Sleep4());
    return;
}