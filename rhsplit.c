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
#include <zlib.h>

#include "list.h"

static int verbose = 0;

#define AVG_BLOCK_SIZE 0x100000
#define MIN_BLOCK_SIZE (AVG_BLOCK_SIZE / 4)

struct direntry
{
    struct list entry;
    int compressed;  /* the file appears to be compressed */
    int keep;  /* keep the file after the script completes */
    char name[0];
};

struct tempfile
{
    SHA256_CTX sha256;
    size_t len;

    /* uncompressed file */
    int fd;
    FILE *file;

    /* compressed file */
    int gzfd;
    gzFile gzfile;
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

static void tempfile_free(struct tempfile *tempfile)
{
    if (!tempfile)
        return;

    if (tempfile->fd != -1) close(tempfile->fd);
    if (tempfile->file) fclose(tempfile->file);
    if (tempfile->gzfd != -1) close(tempfile->gzfd);
    if (tempfile->gzfile) gzclose(tempfile->gzfile);
    free(tempfile);
}

static struct tempfile *open_tempfile(int base_fd, int compression)
{
    struct tempfile *tempfile;
    int fd;

    if (!(tempfile = malloc(sizeof(*tempfile))))
    {
        perror("malloc");
        return NULL;
    }

    tempfile->fd = -1;
    tempfile->file = NULL;
    tempfile->gzfd = -1;
    tempfile->gzfile = NULL;

    if (compression <= 1)
    {
        if ((fd = openat(base_fd, ".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR)) == -1)
        {
            perror("open");
            goto error;
        }
        if ((tempfile->fd = dup(fd)) == -1)
        {
            perror("dup");
            close(fd);
            goto error;
        }
        if (!(tempfile->file = fdopen(fd, "wb")))
        {
            perror("fdopen");
            close(fd);
            goto error;
        }
    }

    if (compression >= 1)
    {
        if ((fd = openat(base_fd, ".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR)) == -1)
        {
            perror("open");
            goto error;
        }
        if ((tempfile->gzfd = dup(fd)) == -1)
        {
            perror("dup");
            close(fd);
            goto error;
        }
        if (!(tempfile->gzfile = gzdopen(fd, "wb")))
        {
            perror("gzdopen");
            close(fd);
            goto error;
        }
    }

    SHA256_Init(&tempfile->sha256);
    tempfile->len = 0;

    return tempfile;

error:
    tempfile_free(tempfile);
    return NULL;
}

static int tempfile_write(struct tempfile *tempfile, uint8_t *buf, size_t len)
{
    if (!len)
        return 0;

    if (tempfile->file && fwrite(buf, len, 1, tempfile->file) != 1)
    {
        fprintf(stderr, "fwrite failed\n");
        return -1;
    }
    if (tempfile->gzfile && gzfwrite(buf, len, 1, tempfile->gzfile) != 1)
    {
        fprintf(stderr, "gzwrite failed\n");
        return -1;
    }

    SHA256_Update(&tempfile->sha256, buf, len);
    tempfile->len += len;
    return 0;
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

static int check_file(int base_fd, char *name, unsigned char *expected_digest)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    char buf[40960];
    size_t read;
    FILE *file;
    int fd;

    if ((fd = openat(base_fd, name, O_RDONLY, S_IRUSR | S_IWUSR)) == -1)
    {
        perror("openat");
        return 0;
    }
    if (!(file = fdopen(fd, "rb")))
    {
        perror("fdopen");
        close(fd);
        return 0;
    }

    SHA256_Init(&sha256);
    while ((read = fread(buf, 1, sizeof(buf), file)))
        SHA256_Update(&sha256, buf, read);

    if (ferror(file))
    {
        fprintf(stderr, "%s: Error while reading file\n", name);
        fclose(file);
        return 0;
    }

    SHA256_Final(digest, &sha256);
    fclose(file);

    if (!memcmp(digest, expected_digest, sizeof(digest)))
        return 1;

    if (verbose) fprintf(stderr, "%s: Checksum mismatch\n", name);
    return 0;
}

static int check_gzfile(int base_fd, char *name, unsigned char *expected_digest)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    char buf[40960];
    int errnum = 0;
    size_t read;
    gzFile file;
    int fd;

    if ((fd = openat(base_fd, name, O_RDONLY, S_IRUSR | S_IWUSR)) == -1)
    {
        perror("openat");
        return 0;
    }
    if (!(file = gzdopen(fd, "rb")))
    {
        perror("gzdopen");
        close(fd);
        return 0;
    }

    if (gzdirect(file))
    {
        fprintf(stderr, "%s: File is not gzip compressed\n", name);
        gzclose(file);
        return 0;
    }

    SHA256_Init(&sha256);
    while ((read = gzfread(buf, 1, sizeof(buf), file)))
        SHA256_Update(&sha256, buf, read);

    gzerror(file, &errnum);
    if (errnum)
    {
        fprintf(stderr, "%s: Error while reading file\n", name);
        gzclose(file);
        return 0;
    }

    SHA256_Final(digest, &sha256);
    gzclose(file);

    if (!memcmp(digest, expected_digest, sizeof(digest)))
        return 1;

    if (verbose) fprintf(stderr, "%s: Checksum mismatch\n", name);
    return 0;
}

static int tempfile_finish(struct tempfile *tempfile, int base_fd, struct list *files, FILE *script)
{
    static const char format_str_gz[] = "zcat %s\n";
    static const char format_str[] = "cat %s\n";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char name[SHA256_DIGEST_LENGTH * 2 + 4];
    struct direntry *entry, *entry2;
    char proc_path[PATH_MAX];
    const char *format;
    int compressed;
    char *ptr;
    int fd;
    int i;

    if (!tempfile->len)
        return 0;

    if (tempfile->file)
    {
        if (fclose(tempfile->file))
        {
            fprintf(stderr, "fclose failed\n");
            return -1;
        }
        tempfile->file = NULL;
    }

    if (tempfile->gzfile)
    {
        if (gzclose(tempfile->gzfile) != Z_OK)
        {
            fprintf(stderr, "gzclose failed\n");
            return -1;
        }
        tempfile->gzfile = NULL;
    }

    SHA256_Final(digest, &tempfile->sha256);

    ptr = name;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(ptr, "%02x", digest[i]);
        ptr += 2;
    }

    LIST_FOR_EACH_SAFE(entry, entry2, files, struct direntry, entry)
    {
        if (strncmp(entry->name, name, SHA256_DIGEST_LENGTH * 2))
            continue;

        if (!entry->keep)
        {
            if (entry->compressed)
                entry->keep = check_gzfile(base_fd, entry->name, digest);
            else
                entry->keep = check_file(base_fd, entry->name, digest);
        }

        if (entry->keep)
        {
            format = entry->compressed ? format_str_gz : format_str;
            if (fprintf(script, format, entry->name) < 0)
            {
                fprintf(stderr, "fprintf failed\n");
                return -1;
            }

            if (verbose) fprintf(stderr, "%s: Reusing existing file\n", entry->name);
            return 0;
        }

        /* the file is invalid, delete it */
        if (verbose) fprintf(stderr, "%s: Deleting\n", entry->name);
        unlinkat(base_fd, entry->name, 0);
        list_remove(&entry->entry);
        free(entry);
    }

    if (tempfile->fd != -1 && tempfile->gzfd != -1)
    {
        struct stat stat, gzstat;

        if (fstat(tempfile->fd, &stat) ||
            fstat(tempfile->gzfd, &gzstat))
        {
            perror("fstat");
            return -1;
        }

        compressed = (gzstat.st_size + 4096 < stat.st_size);
    }
    else
    {
        compressed = (tempfile->gzfd != -1);
    }

    if (compressed)
        strcat(name, ".gz");

    format = compressed ? format_str_gz : format_str;
    if (fprintf(script, format, name) < 0)
    {
        fprintf(stderr, "fprintf failed\n");
        return -1;
    }

    fd = compressed ? tempfile->gzfd : tempfile->fd;
    sprintf(proc_path, "/proc/self/fd/%d", fd);
    assert(fd != -1);

    if (linkat(AT_FDCWD, proc_path, base_fd, name, AT_SYMLINK_FOLLOW))
    {
        perror("linkat");
        return -1;
    }

    if (!(entry = malloc(offsetof(struct direntry, name[strlen(name) + 1]))))
    {
        perror("malloc");
        return -1;
    }

    entry->compressed = compressed;
    entry->keep = 1;
    strcpy(entry->name, name);
    list_add_tail(files, &entry->entry);

    if (verbose) fprintf(stderr, "%s: Created\n", name);
    return 0;
}

static void unlink_files(int base_fd, struct list *files)
{
    struct direntry *entry, *entry2;

    LIST_FOR_EACH_SAFE(entry, entry2, files, struct direntry, entry)
    {
        if (!entry->keep)
        {
            if (verbose) fprintf(stderr, "%s: Deleting\n", entry->name);
            unlinkat(base_fd, entry->name, 0);
        }
        free(entry);
    }
}

static void free_files(struct list *files)
{
    struct direntry *entry, *entry2;

    LIST_FOR_EACH_SAFE(entry, entry2, files, struct direntry, entry)
    {
        free(entry);
    }
}

static int read_directory(int base_fd, struct list *files)
{
    struct direntry *entry;
    struct dirent *dirent;
    const char *name;
    int compressed;
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

        for (i = 0; i < SHA256_DIGEST_LENGTH * 2; i++)
        {
            if (!(name[i] >= '0' && name[i] <= '9') &&
                !(name[i] >= 'a' && name[i] <= 'f'))
            {
                fprintf(stderr, "%s: Unexpected file\n", name);
                closedir(dir);
                return -1;
            }
        }

        if (!strcmp(&name[SHA256_DIGEST_LENGTH * 2], ".gz"))
            compressed = 1;
        else if (!name[SHA256_DIGEST_LENGTH * 2])
            compressed = 0;
        else
        {
            fprintf(stderr, "%s: Unexpected file\n", name);
            closedir(dir);
            return -1;
        }

        if (!(entry = malloc(offsetof(struct direntry, name[strlen(name) + 1]))))
        {
            perror("malloc");
            closedir(dir);
            return -1;
        }

        entry->compressed = compressed;
        entry->keep = 0;
        strcpy(entry->name, name);
        list_add_tail(files, &entry->entry);
    }

    closedir(dir);
    return 0;
}

void show_help(const char *program_name)
{
    fprintf(stderr, "Usage: %s [OPTION]... [DIRECTORY]...\n", program_name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Read large binary files from stdin and split them based on a running hash\n");
    fprintf(stderr, "function. The parts are stored in DIRECTORY, along with a script to recreate\n");
    fprintf(stderr, "the original file.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -h  show this help\n");
    fprintf(stderr, "  -v  enable verbose mode\n");
    fprintf(stderr, "  -z  use gzip compression when it decreases the file size\n");
    fprintf(stderr, "  -Z  enable gzip compression for all blocks\n");
    fprintf(stderr, "\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char name[SHA256_DIGEST_LENGTH * 2 + 1];
    const char *base_path = NULL;
    struct tempfile *out = NULL;
    SHA256_CTX sha256;
    size_t read, start;
    struct rhash rhash;
    struct list files;
    int compression = 0;
    FILE *script = NULL;
    int options = 1;
    uint8_t buf[40960];
    int base_fd;
    char *ptr;
    int i;

    for (i = 1; i < argc; i++)
    {
        if (options && !strcmp(argv[i], "-Z")) compression = 2;
        else if (options && !strcmp(argv[i], "-z")) compression = 1;
        else if (options && !strcmp(argv[i], "-v")) verbose = 1;
        else if (options && !strcmp(argv[i], "-h")) show_help(argv[0]);
        else if (options && !strcmp(argv[i], "--")) options = 0;
        else if (!base_path) base_path = argv[i];
        else show_help(argv[0]);
    }

    if (!base_path)
    {
        show_help(argv[0]);
        return 1;
    }
    if ((base_fd = open(base_path, O_DIRECTORY | O_PATH | O_RDWR)) == -1)
    {
        perror("open");
        return 1;
    }

    list_init(&files);
    if (read_directory(base_fd, &files))
        goto error;

    if (!(script = open_script(base_fd)))
        goto error;

    if (!(out = open_tempfile(base_fd, compression)))
        goto error;

    SHA256_Init(&sha256);
    rhash_init(&rhash);

    while ((read = fread(buf, 1, sizeof(buf), stdin)))
    {
        SHA256_Update(&sha256, buf, read);

        start = 0;
        for (i = 0; i < read; i++)
        {
            if (!rhash_update(&rhash, buf[i]))
                continue;

            if (tempfile_write(out, &buf[start], i + 1 - start))
                goto error;

            start = i + 1;
            if (out->len < MIN_BLOCK_SIZE)
                continue;

            if (tempfile_finish(out, base_fd, &files, script))
                goto error;

            tempfile_free(out);
            if (!(out = open_tempfile(base_fd, compression)))
                goto error;

            rhash_init(&rhash);
        }

        if (tempfile_write(out, &buf[start], read - start))
            goto error;
    }

    if (tempfile_finish(out, base_fd, &files, script))
        goto error;

    tempfile_free(out);
    out = NULL;

    SHA256_Final(digest, &sha256);

    ptr = name;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(ptr, "%02x", digest[i]);
        ptr += 2;
    }

    if (fprintf(script, "\n# SHA256: %s\n", name) < 0)
    {
        fprintf(stderr, "fprintf failed\n");
        goto error;
    }
    if (fclose(script))
    {
        fprintf(stderr, "fclose failed\n");
        goto error;
    }
    script = NULL;

    unlink_files(base_fd, &files);
    close(base_fd);
    return 0;

error:
    if (script) fclose(script);
    tempfile_free(out);
    free_files(&files);
    close(base_fd);
    return 1;
}
