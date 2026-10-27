# level03 : reverse / keygen (XOR)

```c
int decrypt(int key)
{
    char str[17];

    strncpy(str, "Q}|u`sfg~sf{}|a3", 17);
    for (int i = 0; i < strlen(str); i++)
        str[i] ^= key;

    if (strncmp(str, "Congratulations!", 17) == 0)
        return system("/bin/sh");
    else
        return puts("\nInvalid Password");
}

void test(unsigned int input, unsigned int magic)
{
    unsigned int key = magic - input;

    switch (key) {
        case 1: case 2: case 3: case 4: case 5:
        case 6: case 7: case 8: case 9:
        case 16: case 17: case 18: case 19: case 20: case 21:
            decrypt(key);
            break;
        default:
            decrypt(rand());
    }
}

int main(void)
{
    unsigned int input;

    srand(time(NULL));
    puts("***********************************");
    puts("*\t\tlevel03\t\t**");
    puts("***********************************");
    printf("Password:");
    scanf("%d", &input);
    test(input, 322424845);
    return 0;
}
```

decrypt XOR la chaine "Q}|u`sfg~sf{}|a3" avec une cle et compare a "Congratulations!". la cle vaut `322424845 - input` et doit tomber dans le switch (1-9, 16-21).

chaine chiffree / cible :

    Q}|u`sfg~sf{}|a3   ->   Congratulations!

brute force XOR (CyberChef, cle en hex) :

    https://gchq.github.io/CyberChef/

    Key = 10: Amlepcvwncvkmlq#
    Key = 11: @lmdqbwvobwjlmp"
    Key = 12: Congratulations!
    Key = 13: Bnofs`utm`uhnor 
    Key = 14: Eihatgrsjgroihu'

    0x12 = 18

input a entrer = 322424845 - 18 :

    322424827
