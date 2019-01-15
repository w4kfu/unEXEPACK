#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <stdlib.h>
#include <string.h>

#if !defined(_MSC_VER)
    #include <unistd.h>
#else
    #pragma warning(disable : 4013)
#endif

#ifndef O_BINARY
    #define O_BINARY 0
#endif

#define DOS_SIGNATURE 0x5A4D
#define EXEPACK_SIGNATURE 0x4252

#define STR(x) #x
#define XSTR(x) STR(x)
#define XPERROR(fname)                                      \
    perror(XSTR(__FUNCTION__) " - " fname "() ");           \
    exit(EXIT_FAILURE);
#define PERROR(fname)                                       \
    perror(XSTR(__FUNCTION__) " - " fname "() ");
#define XERROR(Format, ...)                                             \
    fprintf (stderr, "%s - " Format "\n", __FUNCTION__, ##__VA_ARGS__); \
    exit(EXIT_FAILURE);

struct memstream {
    unsigned char *buf;
    unsigned int length;
    unsigned int pos;
};

struct dos_header {
    unsigned short e_magic;
    unsigned short e_cblp;
    unsigned short e_cp;
    unsigned short e_crlc;
    unsigned short e_cparhdr;
    unsigned short e_minalloc;
    unsigned short e_maxalloc;
    unsigned short e_ss;
    unsigned short e_sp;
    unsigned short e_csum;
    unsigned short e_ip;
    unsigned short e_cs;
    unsigned short e_lfarlc;
    unsigned short e_ovno;
};

struct exepack_header {
    unsigned short real_ip;
    unsigned short real_cs;
    unsigned short mem_start;
    unsigned short exepack_size;
    unsigned short real_sp;
    unsigned short real_ss;
    unsigned short dest_len;
    unsigned short skip_len;
    unsigned short signature;
};


void reverse(unsigned char *s, size_t length);
void unpack_data(unsigned char *unpacked_data, unsigned char *buf, unsigned int unpacked_data_size, unsigned int packed_data_len);
void unpack(struct memstream *ms);
unsigned char *create_reloc_table(struct memstream *ms, struct dos_header *dh, struct exepack_header *eh, unsigned int *reloc_table_size);
void writeexe(struct dos_header *dh, struct exepack_header *eh, unsigned char *unpacked_data, unsigned char *reloc, size_t reloc_size, size_t padding);
void craftexec(struct dos_header *dh, struct exepack_header *eh, unsigned char *unpacked_data, unsigned char *reloc, unsigned int reloc_size);

/*
    utils
*/
int test_dos_header(struct memstream *ms);
void msopen(const char *filename, struct memstream *ms);
unsigned int msread(struct memstream *ms, void *buf, unsigned int count);
int mscanread(struct memstream *ms, unsigned int count);
unsigned int msgetavailable(struct memstream *ms);
void msseek(struct memstream *ms, unsigned int offset);
void msclose(struct memstream *ms);
void *memmem(const void *l, size_t l_len, const void *s, size_t s_len);
void hexdump(void *data, int size);

void print_dos_header(struct dos_header *dh)
{
    printf("e_magic    = 0x%04X\n", dh->e_magic);
    printf("e_cblp     = 0x%04X\n", dh->e_cblp);
    printf("e_cp       = 0x%04X\n", dh->e_cp);
    printf("e_crlc     = 0x%04X\n", dh->e_crlc);
    printf("e_cparhdr  = 0x%04X\n", dh->e_cparhdr);
    printf("e_minalloc = 0x%04X\n", dh->e_minalloc);
    printf("e_maxalloc = 0x%04X\n", dh->e_maxalloc);
    printf("e_ss       = 0x%04X\n", dh->e_ss);
    printf("e_sp       = 0x%04X\n", dh->e_sp);
    printf("e_csum     = 0x%04X\n", dh->e_csum);
    printf("e_ip       = 0x%04X\n", dh->e_ip);
    printf("e_cs       = 0x%04X\n", dh->e_cs);
    printf("e_lfarlc   = 0x%04X\n", dh->e_lfarlc);
    printf("e_ovno     = 0x%04X\n", dh->e_ovno);
}

void print_exepack_header(struct exepack_header *eh)
{
    printf("real_ip         = 0x%04X\n", eh->real_ip);
    printf("real_cs         = 0x%04X\n", eh->real_cs);
    printf("mem_start       = 0x%04X\n", eh->mem_start);
    printf("exepack_size    = 0x%04X\n", eh->exepack_size);
    printf("real_sp         = 0x%04X\n", eh->real_sp);
    printf("real_ss         = 0x%04X\n", eh->real_ss);
    if (eh->skip_len == EXEPACK_SIGNATURE) {
        printf("signature       = 0x%04X\n", eh->skip_len);
    }
    else {
        printf("skip_len        = 0x%04X\n", eh->skip_len);
        printf("signature       = 0x%04X\n", eh->signature);
    }
}

void reverse(unsigned char *s, size_t length)
{
    size_t i, j;
    unsigned char c;

    for (i = 0, j = length - 1; i < j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

/* buf is already reversed, because EXEPACK use backward processing */
void unpack_data(unsigned char *unpacked_data, unsigned char *buf, unsigned int unpacked_data_size, unsigned int packed_data_len)
{
    unsigned char opcode;
    unsigned short count;
    unsigned char fillbyte;
    unsigned char *save_buf = NULL;
    unsigned char *save_unp = NULL;
    unsigned int cur_unpacked_data_size = 0x00;

    save_buf = buf;
    save_unp = unpacked_data;
    while (*buf == 0xFF) {
        buf++;
    }
    while (1) {
        opcode = *buf++;
        count = *(buf) * 0x100 + *(buf + 1);
        buf += 2;
        if ((opcode & 0xFE) == 0xB0) {
            fillbyte = *buf++;
            if ((cur_unpacked_data_size + count) > unpacked_data_size) {
                XERROR("overflow");
            }
            memset(unpacked_data, fillbyte, count);
            unpacked_data += count;
            cur_unpacked_data_size += count;
        }
        else if ((opcode & 0xFE) == 0xB2) {
            if ((cur_unpacked_data_size + count) > unpacked_data_size) {
                XERROR("overflow");
            }
            memcpy(unpacked_data, buf, count);
            unpacked_data += count;
            cur_unpacked_data_size += count;
            buf += count;
        }
        else {
            XERROR("unknown opcode");
        }
        if ((opcode & 1) == 1) {
            break;
        }
    }
    if (buf - save_buf != packed_data_len) {
        if ((packed_data_len - (buf - save_buf)) > (unpacked_data_size - (unpacked_data - save_unp))) {
            XERROR("Data left are too large!");
        }
        memcpy(unpacked_data, buf, packed_data_len - (buf - save_buf));
    }
}

unsigned char *create_reloc_table(struct memstream *ms, struct dos_header *dh, struct exepack_header *eh, unsigned int *reloc_table_size)
{
    unsigned int exepack_offset = 0x00;
    unsigned int reloc_length;
    int nb_reloc;
    unsigned char *buf_reloc = NULL;
    unsigned char *reloc = NULL;
    int i, j;
    int count;
    unsigned short entry;

    exepack_offset = (dh->e_cparhdr + dh->e_cs) * 16;
    msseek(ms, exepack_offset);
    reloc = memmem(ms->buf + exepack_offset, msgetavailable(ms), "Packed file is corrupt", strlen("Packed file is corrupt"));
    if (!reloc) {
        XERROR("Cannot find string \"Packed file is corrupt\", is it really EXEPACK ?");
    }

    reloc_length = (unsigned int)(eh->exepack_size - ((reloc - (ms->buf + exepack_offset)) & 0xFFFFFFFF) + strlen("Packed file is corrupt"));
    nb_reloc = (reloc_length - 16 * sizeof (unsigned short)) / 2;
    *reloc_table_size = nb_reloc * 2 * sizeof(unsigned short);
    buf_reloc = malloc(sizeof (char) * *reloc_table_size);
    if (buf_reloc == NULL) {
        XPERROR("malloc");
    }
    reloc += strlen("Packed file is corrupt");
    *reloc_table_size = 0;
    msseek(ms, (reloc - ms->buf) & 0xFFFFFFFF);

    for (i = 0; i < 16; i++) {
        if (msread(ms, &count, sizeof (unsigned short)) != sizeof (unsigned short)) {
            XERROR("msread failed");
        }
        for (j = 0; j < count; j++) {
            if (msread(ms, &entry, sizeof (unsigned short)) != sizeof (unsigned short)) {
                XERROR("msread failed");
            }
            *(unsigned short*)(buf_reloc + *reloc_table_size) = entry;
            *reloc_table_size += 2;
            *(unsigned short*)(buf_reloc + *reloc_table_size) = (i * 0x1000) & 0xFFFF;
            *reloc_table_size += 2;
        }
    }
    return buf_reloc;
}

void writeexe(struct dos_header *dhead, struct exepack_header *eh, unsigned char *unpacked_data, unsigned char *reloc, size_t reloc_size, size_t padding)
{
    int fd;
    int i;

    fd = open("unpacked", O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
    if (fd == -1) {
        XPERROR("open");
    }
    write(fd, dhead, sizeof (struct dos_header));
    write(fd, reloc, reloc_size);
    for (i = 0; i < padding; i++) {
        write(fd, "\x00", 1);
    }
    write(fd, unpacked_data, eh->dest_len * 16);
    close(fd);
}

void craftexec(struct dos_header *dh, struct exepack_header *eh, unsigned char *unpacked_data, unsigned char *reloc, unsigned int reloc_size)
{
    struct dos_header dhead;
    int header_size;
    int total_length;
    int padding_length;

    memset(&dhead, 0, sizeof (struct dos_header));
    header_size = sizeof (struct dos_header) + reloc_size;
    dhead.e_magic = DOS_SIGNATURE;
    dhead.e_cparhdr = (header_size / 16) & 0xFFFF;
    dhead.e_cparhdr = (dhead.e_cparhdr / 32 + 1) * 32;
    padding_length = dhead.e_cparhdr * 16 - header_size;
    total_length = header_size + padding_length + eh->dest_len * 16;
    dhead.e_ss = eh->real_ss;
    dhead.e_sp = eh->real_sp;
    dhead.e_ip = eh->real_ip;
    dhead.e_cs = eh->real_cs;
    dhead.e_minalloc = dh->e_minalloc;
    dhead.e_maxalloc = 0xFFFF;
    dhead.e_lfarlc = sizeof (struct dos_header);
    dhead.e_crlc = (reloc_size / (2 * sizeof (unsigned short))) & 0xFFFF;
    dhead.e_cblp = total_length % 512;
    dhead.e_cp = (total_length / 512 + 1) & 0xFFFF;
    print_dos_header(&dhead);
    writeexe(&dhead, eh, unpacked_data, reloc, reloc_size, padding_length);
}

void unpack(struct memstream *ms)
{
    struct dos_header dh;
    struct exepack_header eh;
    unsigned int exepack_offset = 0x00;
    unsigned char *unpacked_data = NULL;
    unsigned int unpacked_data_size = 0x00;
    unsigned int packed_data_start;
    unsigned int packed_data_end;
    unsigned int packed_data_len;
    unsigned int reloc_size;
    unsigned char *reloc = NULL;

    if (msread(ms, &dh, sizeof (struct dos_header)) != sizeof (struct dos_header)) {
        return;
    }
    print_dos_header(&dh);
    exepack_offset = (dh.e_cparhdr + dh.e_cs) * 16;
    msseek(ms, exepack_offset);
    if (msread(ms, &eh, sizeof (struct exepack_header)) != sizeof (struct exepack_header)) {
        return;
    }
    print_exepack_header(&eh);
    if ((eh.signature != EXEPACK_SIGNATURE && eh.skip_len != EXEPACK_SIGNATURE) || eh.exepack_size == 0x00) {
        XERROR("This is not a valid EXEPACK executable");
        return;
    }
    printf("Header exepack = %X\n", exepack_offset);
    print_exepack_header(&eh);
    unpacked_data_size = eh.dest_len * 16;
    unpacked_data = malloc(sizeof (char) * unpacked_data_size);
    if (unpacked_data == NULL) {
        XPERROR("malloc");
    }
    packed_data_start = dh.e_cparhdr * 16;
    packed_data_end = exepack_offset;
    packed_data_len = packed_data_end - packed_data_start;
    msseek(ms, packed_data_start);
    if (mscanread(ms, packed_data_len) == 0x00) {
        free(unpacked_data);
        return;
    }
    reverse(ms->buf + packed_data_start, packed_data_len);
    unpack_data(unpacked_data, ms->buf + packed_data_start, unpacked_data_size, packed_data_len);
    reverse(unpacked_data, unpacked_data_size);
    reloc = create_reloc_table(ms, &dh, &eh, &reloc_size);
    craftexec(&dh, &eh, unpacked_data, reloc, reloc_size);
    free(unpacked_data);
}

int main(int argc, char *argv[])
{
    struct memstream ms;

    if (argc != 2) {
        fprintf(stderr, "%s <EXEPACK_file>; ouput file is \"unpacked\"\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    msopen(argv[1], &ms);
    if (test_dos_header(&ms) == 0) {
        fprintf(stderr, "%s is not a valid MS-DOS executable\n", argv[1]);
        msclose(&ms);
        exit(EXIT_FAILURE);
    }
    unpack(&ms);
    msclose(&ms);
    return 0;
}

void hexdump(void *data, int size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for (n = 1; n <= size; n++) {
        if (n % 16 == 1) {
#ifdef _MSC_VER
        sprintf_s(addrstr, sizeof(addrstr), "%.4x", (unsigned int)(p - (unsigned char*)data));
#else
        snprintf(addrstr, sizeof (addrstr), "%.4x", (p - (unsigned char*)data));
#endif
        }
        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }
#ifdef _MSC_VER
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof(hexstr), bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat_s(charstr, sizeof(charstr), bytestr, sizeof(charstr) - strlen(charstr) - 1);
#else
        snprintf(bytestr, sizeof (bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof (hexstr) - strlen(hexstr) - 1);
        snprintf(bytestr, sizeof (bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof (charstr) - strlen(charstr) - 1);
#endif
        if (n % 16 == 0) {
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0) {
#ifdef _MSC_VER
            strncat_s(hexstr, sizeof(hexstr), "  ", sizeof(hexstr)-strlen(hexstr)-1);
#else
            strncat(hexstr, "  ", sizeof (hexstr) - strlen(hexstr) - 1);
#endif
        }
        p++;
    }
    if (strlen(hexstr) > 0) {
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;

    if (l_len == 0 || s_len == 0) {
        return NULL;
    }
    if (l_len < s_len) {
        return NULL;
    }
    if (s_len == 1) {
        return (void*)memchr(l, (int)*cs, l_len);
    }
    last = (char *)cl + l_len - s_len;
    for (cur = (char *)cl; cur <= last; cur++) {
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0) {
            return cur;
        }
    }
    return NULL;
}

void msopen(const char *filename, struct memstream *ms)
{
    int fd;
    struct stat st;

    if (ms == NULL) {
        exit(EXIT_FAILURE);
    }
    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd == -1) {
        XPERROR("open");
    }
    if (fstat(fd, &st) == -1) {
        close(fd);
        XPERROR("fstat");
    }
    ms->buf = (unsigned char*)malloc(sizeof (char) * st.st_size);
    if (ms->buf == NULL) {
        close(fd);
        XPERROR("malloc()");
    }
    if (read(fd, ms->buf, st.st_size) != st.st_size) {
        close(fd);
        free(ms->buf);
        XPERROR("read()");
    }
    ms->pos = 0x00;
    ms->length = st.st_size;
    close(fd);
}

unsigned int msread(struct memstream *ms, void *buf, unsigned int count)
{
    unsigned int length;

    if (buf == NULL) {
        return 0;
    }
    if (ms->pos > ms->length) {
        XERROR("invalid read");
    }
    if (count < (ms->length - ms->pos)) {
        length = count;
    }
    else {
        length = ms->length - ms->pos;
    }
    if (length > 0) {
        memcpy(buf, ms->buf + ms->pos, length);
    }
    ms->pos += length;
    return length;
}

int mscanread(struct memstream *ms, unsigned int count)
{
    if (ms->pos > ms->length) {
        return 0;
    }
    if (count > (ms->length - ms->pos)) {
        return 0;
    }
    return 1;
}

unsigned int msgetavailable(struct memstream *ms)
{
    if (ms->pos > ms->length) {
        return 0;
    }
    return ms->length - ms->pos;
}

void msseek(struct memstream *ms, unsigned int offset)
{
    if (offset > ms->length) {
        XERROR("invalid seek : 0x%X", offset);
    }
    ms->pos = offset;
}

void msclose(struct memstream *ms)
{
    if (ms != NULL) {
        if (ms->buf != NULL) {
            free(ms->buf);
            ms->buf = NULL;
        }
    }
}

int test_dos_header(struct memstream *ms)
{
    struct dos_header dh;

    if (ms == NULL) {
        return 0;
    }
    if (msread(ms, &dh, sizeof (struct dos_header)) != sizeof (struct dos_header)) {
        return 0;
    }
    msseek(ms, 0x00);
    if (dh.e_magic != DOS_SIGNATURE) {
        return 0;
    }
    /* at least one page */
    if (dh.e_cp == 0) {
        return 0;
    }
    /* last page must not hold 0 bytes */
    if (dh.e_cblp == 0) {
        return 0;
    }
    /* not even number of paragraphs */
    if (dh.e_cparhdr % 2 != 0) {
        return 0;
    }
    return 1;
}