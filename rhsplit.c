#define _GNU_SOURCE
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stddef.h>

#include "list.h"

static const int verbose = 0;

#define AVG_BLOCK_SIZE 0x100000
#define MIN_BLOCK_SIZE (AVG_BLOCK_SIZE / 4)

struct direntry
{
    struct list entry;
    char name[0];
};

struct rhash
{
    uint8_t buf[4096];
    uint16_t a;
    uint16_t b;
    int pos;  /* 0 <= pos < 4095 */
    int len;  /* 0 <= pos <= 4096 */
};

static inline void rhash_init(struct rhash *rhash)
{
    rhash->a = 0;
    rhash->b = 0;
    rhash->pos = 0;
    rhash->len = 0;
}

static inline void rhash_compute(struct rhash *rhash)
{
    uint8_t value;
    int i;

    rhash->a = 0;
    rhash->b = 0;

    for (i = 0; i < rhash->len; i++)
    {
        value = rhash->buf[(rhash->pos + i) % sizeof(rhash->buf)];
        rhash->a += value;
        rhash->b += (sizeof(rhash->buf) - i) * value;
    }
}

static inline int rhash_update(struct rhash *rhash, uint8_t value)
{
    uint8_t old_value;
    uint32_t rh;
    int i;

    if (rhash->len < sizeof(rhash->buf))
    {
        rhash->buf[(rhash->pos + rhash->len) % sizeof(rhash->buf)] = value;
        rhash->len++;
        if (rhash->len < sizeof(rhash->buf))
            return 0;

        rhash_compute(rhash);
    }
    else
    {
        old_value = rhash->buf[rhash->pos];
        rhash->buf[rhash->pos] = value;
        rhash->pos = (rhash->pos + 1) % sizeof(rhash->buf);

        rhash->a += value - old_value;
        rhash->b += rhash->a - sizeof(rhash->buf) * old_value;

        /*
        uint16_t old_a = rhash->a;
        uint64_t old_b = rhash->b;

        rhash_compute(rhash);

        assert(rhash->a == old_a);
        assert(rhash->b == old_b);
        */
    }

    rh = (uint32_t)rhash->a + ((uint32_t)rhash->b << 16);

    /* Murmur scamble */
    rh *= 0xcc9e2d51;
    rh = (rh << 15) | (rh >> 17);
    rh *= 0x1b873593;

    return !(rh % AVG_BLOCK_SIZE);
}

static FILE *open_script(int base_fd)
{
    static const char cmd_header[] = "#!/bin/bash\n\nset -e\ncd \"$(dirname \"$0\")\"\n\n";
    FILE *file;
    int fd;

    if ((fd = openat(base_fd, "unpack", O_RDWR | O_CREAT | O_TRUNC,
                     S_IRUSR | S_IWUSR | S_IXUSR)) == -1)
    {
        perror("open");
        return NULL;
    }

    if (!(file = fdopen(fd, "wb+")))
    {
        perror("fdopen");
        close(fd);
        return NULL;
    }

    if (fwrite(cmd_header, strlen(cmd_header), 1, file) != 1)
    {
        fprintf(stderr, "fwrite failed\n");
        fclose(file);
        return NULL;
    }

    return file;
}

static FILE *open_tempfile(int base_fd)
{
    FILE *file;
    int fd;

    if ((fd = openat(base_fd, ".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR)) == -1)
    {
        perror("open");
        return NULL;
    }

    if (!(file = fdopen(fd, "wb+")))
    {
        perror("fdopen");
        close(fd);
        return NULL;
    }

    assert(fileno(file) == fd);
    return file;
}

static DIR *opendirat(int dir_fd, char const *path)
{
    DIR *dir;
    int fd;

    if ((fd = openat(dir_fd, path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOCTTY)) == -1)
        return NULL;

    if (!(dir = fdopendir(fd)))
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return NULL;
    }

    return dir;
}

static int check_file(int base_fd, char *name)
{
    unsigned char digest[SHA256_DIGEST_LENGTH + 1];
    char new_name[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256_CTX sha256;
    char buf[40960];
    char *ptr;
    size_t read;
    FILE *file;
    int fd;
    int i;

    if ((fd = openat(base_fd, name, O_RDONLY, S_IRUSR | S_IWUSR)) == -1)
    {
        perror("openat");
        return -1;
    }

    if (!(file = fdopen(fd, "rb")))
    {
        perror("fdopen");
        close(fd);
        return -1;
    }

    SHA256_Init(&sha256);
    while ((read = fread(buf, 1, sizeof(buf), file)))
        SHA256_Update(&sha256, buf, read);

    SHA256_Final(digest, &sha256);
    fclose(file);

    ptr = new_name;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(ptr, "%02x", digest[i]);
        ptr += 2;
    }

    if (!strcmp(name, new_name))
        return 0;

    if (verbose) fprintf(stderr, "%s: Checksum mismatch\n", name);
    return -1;
}

static int link_file(int base_fd, struct list *files, int fd, SHA256_CTX *sha256, FILE *script)
{
    static const char cmd_prefix[] = "cat ";
    static const char cmd_suffix[] = "\n";
    unsigned char digest[SHA256_DIGEST_LENGTH + 1];
    char name[SHA256_DIGEST_LENGTH * 2 + 1];
    char proc_path[PATH_MAX];
    struct direntry *entry;
    char *ptr;
    int i;

    SHA256_Final(digest, sha256);

    ptr = name;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(ptr, "%02x", digest[i]);
        ptr += 2;
    }

    if (fwrite(cmd_prefix, strlen(cmd_prefix), 1, script) != 1 ||
        fwrite(name, strlen(name), 1, script) != 1 ||
        fwrite(cmd_suffix, strlen(cmd_suffix), 1, script) != 1)
    {
        fprintf(stderr, "fwrite failed\n");
        return -1;
    }

    LIST_FOR_EACH(entry, files, struct direntry, entry)
    {
        if (!strcmp(entry->name, name))
        {
            list_remove(&entry->entry);
            free(entry);

            if (!check_file(base_fd, name))
            {
                if (verbose) fprintf(stderr, "%s: reusing existing file\n", name);
                return 0;
            }

            /* delete the file and create from scratch */
            unlinkat(base_fd, name, 0);
            break;
        }
    }

    sprintf(proc_path, "/proc/self/fd/%d", fd);
    if (linkat(AT_FDCWD, proc_path, base_fd, name, AT_SYMLINK_FOLLOW))
    {
        if (errno == EEXIST)
        {
            /* We must have created it before. This means the checksum has
             * already been verified. */
            return 0;
        }

        perror("linkat");
        return -1;
    }

    if (verbose) fprintf(stderr, "%s: created\n", name);
    return 0;
}

static void unlink_files(int base_fd, struct list *files)
{
    struct direntry *entry, *entry2;

    LIST_FOR_EACH_SAFE(entry, entry2, files, struct direntry, entry)
    {
        if (verbose) fprintf(stderr, "%s: deleting\n", entry->name);
        unlinkat(base_fd, entry->name, 0);
        free(entry);
    }
}

static int read_directory(int base_fd, struct list *files)
{
    struct dirent *dirent;
    struct direntry *entry;
    const char *name;
    DIR *dir;
    int i;

    if (!(dir = opendirat(base_fd, ".")))
    {
        perror("opendirat");
        return -1;
    }

    while ((dirent = readdir(dir)) != NULL)
    {
        name = dirent->d_name;

        if (!strcmp(name, ".") || !strcmp(name, ".."))
            continue;
        if (!strcmp(name, "unpack"))
            continue;

        if (strlen(name) != SHA256_DIGEST_LENGTH * 2)
        {
            fprintf(stderr, "%s: unexpected file\n", name);
            closedir(dir);
            return -1;
        }

        for (i = 0; i < SHA256_DIGEST_LENGTH * 2; i++)
        {
            if (!(name[i] >= '0' && name[i] <= '9') &&
                !(name[i] >= 'a' && name[i] <= 'f'))
            {
                fprintf(stderr, "%s: unexpected file\n", name);
                closedir(dir);
                return -1;
            }
        }

        if (!(entry = malloc(offsetof(struct direntry, name[strlen(name) + 1]))))
        {
            perror("malloc");
            closedir(dir);
            return -1;
        }

        strcpy(entry->name, name);
        list_add_tail(files, &entry->entry);
    }

    closedir(dir);
    return 0;
}

int main(int argc, char *argv[])
{
    size_t read, start, i, len, out_len;
    struct list files;
    uint8_t buf[40960];
    struct rhash rhash;
    SHA256_CTX sha256;
    FILE *script, *out;
    int base_fd;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s [DIRECTORY]\n", argv[0]);
        return 1;
    }

    if ((base_fd = open(argv[1], O_DIRECTORY | O_PATH | O_RDWR)) == -1)
    {
        perror("open");
        return 1;
    }

    list_init(&files);
    if (read_directory(base_fd, &files))
    {
        close(base_fd);
        return 1;
    }

    if (!(script = open_script(base_fd)))
    {
        /* FIXME: free linked list */
        close(base_fd);
        return 1;
    }

    if (!(out = open_tempfile(base_fd)))
    {
        /* FIXME: free linked list */
        close(base_fd);
        return 1;
    }

    rhash_init(&rhash);
    SHA256_Init(&sha256);
    out_len = 0;

    while ((read = fread(buf, 1, sizeof(buf), stdin)))
    {
        start = 0;
        for (i = 0; i < read; i++)
        {
            if (!rhash_update(&rhash, buf[i]))
                continue;

            len = i + 1 - start;
            SHA256_Update(&sha256, &buf[start], len);
            if (fwrite(&buf[start], len, 1, out) != 1)
            {
                fprintf(stderr, "fwrite failed\n");
                /* FIXME: Cleanup */
                return 1;
            }
            out_len += i;
            start = i + 1;

            if (out_len < MIN_BLOCK_SIZE)
                continue;

            /* Flush output, start a new file */

            fflush(out);
            if (link_file(base_fd, &files, fileno(out), &sha256, script))
            {
                /* FIXME: Cleanup */
                return 1;
            }
            fclose(out);

            if (!(out = open_tempfile(base_fd)))
            {
                /* FIXME: Cleanup */
                return 1;
            }

            rhash_init(&rhash);
            SHA256_Init(&sha256);
            out_len = 0;
        }

        if ((len = read - start))
        {
            SHA256_Update(&sha256, &buf[start], len);
            if (fwrite(&buf[start], len, 1, out) != 1)
            {
                fprintf(stderr, "fwrite failed\n");
                /* FIXME: Cleanup */
                return 1;
            }
            out_len += len;
        }
    }

    fflush(out);
    if (out_len && link_file(base_fd, &files, fileno(out), &sha256, script))
    {
        /* FIXME: Cleanup */
        return 1;
    }
    fclose(out);

    fflush(script);
    fclose(script);

    unlink_files(base_fd, &files);
    close(base_fd);
    return 0;
}
