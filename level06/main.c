#include <stdio.h>
#include <string.h>


int main (int argc, const char **argv) {
    int i;
    int v4;
    int v5;


    if (strlen(argv[1]) <= 5) {
        return 1;
    }
    v5 = strnlen(argv[1], 32);
    v4 = (argv[1][3] ^ 0x1337) + 6221293;
    for ( i = 0; i < v5; ++i )
    {
      if ( argv[1][i] <= 31 ) {
        printf("Check true: %d\n", v4);
        return 1;
      }
      v4 += (v4 ^ (unsigned int)argv[1][i]) % 0x539;
    }
    printf("Check fin: %d\n", v4);
    return 0;           
}