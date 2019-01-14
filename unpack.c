#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>


#include <stdlib.h>
#include <string.h>

#if !defined(_MSC_VER)
    #include <unistd.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define EXEPACK_SIGNATURE 0x4252

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

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len);
void hex_dump(void *data, int size);
void reverse(unsigned char *s, size_t length);
void unpack_data(unsigned char *unpacked_data, unsigned char *buf, unsigned int unpacked_data_size, unsigned int packed_data_len);
unsigned char *create_reloc_table(unsigned char *buf_load, struct dos_header *dh, struct exepack_header *eh, int *reloc_table_size);
void writeexe(struct dos_header *dhead, struct exepack_header *eh, unsigned char *unpacked_data, unsigned char *reloc, size_t reloc_size, size_t padding);
void craftexec(unsigned char *buf_load, struct dos_header *dh, struct exepack_header *eh, unsigned char *unpacked_data);
void unpack(unsigned char *buf_load, struct dos_header *dh);
int test_dos_header(struct dos_header *dh);

void print_dos_header(struct dos_header *dh)
{
    printf("e_magic    = %04X\n", dh->e_magic);
    printf("e_cblp     = %04X\n", dh->e_cblp);
    printf("e_cp       = %04X\n", dh->e_cp);
    printf("e_crlc     = %04X\n", dh->e_crlc);
    printf("e_cparhdr  = %04X\n", dh->e_cparhdr);
    printf("e_minalloc = %04X\n", dh->e_minalloc);
    printf("e_maxalloc = %04X\n", dh->e_maxalloc);
    printf("e_ss       = %04X\n", dh->e_ss);
    printf("e_sp       = %04X\n", dh->e_sp);
    printf("e_csum     = %04X\n", dh->e_csum);
    printf("e_ip       = %04X\n", dh->e_ip);
    printf("e_cs       = %04X\n", dh->e_cs);
    printf("e_lfarlc   = %04X\n", dh->e_lfarlc);
    printf("e_ovno     = %04X\n", dh->e_ovno);
}

void print_exepack_header(struct exepack_header *eh)
{
    printf("real_ip         = %04X\n", eh->real_ip);
    printf("real_cs         = %04X\n", eh->real_cs);
    printf("mem_start       = %04X\n", eh->mem_start);
    printf("exepack_size    = %04X\n", eh->exepack_size);
    printf("real_sp         = %04X\n", eh->real_sp);
    printf("real_ss         = %04X\n", eh->real_ss);
    if (eh->skip_len == EXEPACK_SIGNATURE) {
        printf("signature       = %04X\n", eh->skip_len);
    }
    else {
        printf("skip_len        = %04X\n", eh->skip_len);
        printf("signature       = %04X\n", eh->signature);
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
            memset(unpacked_data, fillbyte, count);
            unpacked_data += count;
        }
        else if ((opcode & 0xFE) == 0xB2) {
            memcpy(unpacked_data, buf, count);
            unpacked_data += count;
            buf += count;
        }
        else {
            fprintf(stderr, "Opcode unknow!\n");
            exit(0);
        }
        if ((opcode & 1) == 1) {
            break;
        }
    }
    if (buf - save_buf != packed_data_len) {
        if ((packed_data_len - (buf - save_buf)) > (unpacked_data_size - (unpacked_data - save_unp))) {
            fprintf(stderr, "Data left are too large!\n");
            exit(0);
        }
        memcpy(unpacked_data, buf, packed_data_len - (buf - save_buf));
    }
}

unsigned char *create_reloc_table(unsigned char *buf_load, struct dos_header *dh, struct exepack_header *eh, int *reloc_table_size)
{
    int reloc_length;
    int nb_reloc;
    unsigned char *buf_reloc = NULL;
    unsigned char *reloc = NULL;
    int i, j;
    int count;
    unsigned short entry;

    reloc = memmem((buf_load + ((dh->e_cparhdr + dh->e_cs) * 16)), eh->exepack_size, "Packed file is corrupt", strlen("Packed file is corrupt"));
    if (!reloc) {
        fprintf(stderr, "Cannot find string \"Packed file is corrupt\", is it really EXEPACK ?\n");
        exit(0);
    }
    reloc_length = (int)(eh->exepack_size - ((buf_load + ((dh->e_cparhdr + dh->e_cs) * 16)) - reloc) + strlen("Packed file is corrupt"));
    nb_reloc = (reloc_length - 16 * sizeof (unsigned short)) / 2;
    *reloc_table_size = nb_reloc * 2 * sizeof(unsigned short);
    buf_reloc = malloc(sizeof (char) * *reloc_table_size);
    if (buf_reloc == NULL) {
        perror("malloc()");
        exit(0);
    }
    //reloc = buf_load + ((dh->e_cparhdr + dh->e_cs) * 16 - (eh->skip_len - 1) * 16) + sizeof (struct exepack_header) + 0x105;
    if (strncmp((const char*)reloc, "Packed file is corrupt", strlen("Packed file is corrupt"))) {
        fprintf(stderr, "Cannot find string \"Packed file is corrupt\", is it really EXEPACK ?\n");
        exit(0);
    }
    reloc += strlen("Packed file is corrupt");
    *reloc_table_size = 0;
    for (i = 0; i < 16; i++) {
        count = *(unsigned short*)reloc;
        reloc += 2;
        for (j = 0; j < count; j++) {
            entry = *(unsigned short*)reloc;
            reloc += 2;
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
        perror("open()");
        exit(0);
    }
    write(fd, dhead, sizeof (struct dos_header));
    write(fd, reloc, reloc_size);
    for (i = 0; i < padding; i++) {
        write(fd, "\x00", 1);
    }
    write(fd, unpacked_data, eh->dest_len * 16);
    close(fd);
}

void craftexec(unsigned char *buf_load, struct dos_header *dh, struct exepack_header *eh, unsigned char *unpacked_data)
{
    struct dos_header dhead;
    int header_size;
    int total_length;
    int padding_length;
    int reloc_size;
    unsigned char *reloc = NULL;

    memset(&dhead, 0, sizeof (struct dos_header));
    reloc = create_reloc_table(buf_load, dh, eh, &reloc_size);
    header_size = sizeof (struct dos_header) + reloc_size;
    dhead.e_magic = 0x5A4D;
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
    free(reloc);
}

void unpack(unsigned char *buf_load, struct dos_header *dh)
{
    int exepack_offset;
    struct exepack_header *eh;
    unsigned char *exepack_data = NULL;
    int packed_data_start;
    int packed_data_end;
    int packed_data_len;
    unsigned char *unpacked_data = NULL;

    exepack_offset = (dh->e_cparhdr + dh->e_cs) * 16;
    eh = (struct exepack_header*)(buf_load + exepack_offset);
    if (eh->signature != EXEPACK_SIGNATURE && eh->skip_len != EXEPACK_SIGNATURE) {
        fprintf(stderr, "This is not a valid exepack executable\n");
        return;
    }
    printf("Header exepack = %X\n", exepack_offset);
    print_exepack_header(eh);
    exepack_data = buf_load + exepack_offset + sizeof (struct exepack_header);
    packed_data_start = dh->e_cparhdr * 16;
    //packed_data_end = exepack_offset - (eh->skip_len - 1) * 16;
    packed_data_end = exepack_offset;
    packed_data_len = packed_data_end - packed_data_start;
    printf("PackedDataStart = %X\n", packed_data_start);
    printf("PackedDataEnd = %X\n", packed_data_end);
    printf("PackedDataLen = %X\n", packed_data_len);
    unpacked_data = malloc(sizeof (char) * (eh->dest_len) * 16);
    if (unpacked_data == NULL) {
        perror("malloc()");
        return;
    }
    printf("UnpackedDataLen = %X\n", eh->dest_len * 16);
    printf("OFFSET = %llX\n", (buf_load + packed_data_end - 1) - buf_load);
    reverse(buf_load + packed_data_start, packed_data_len);
    unpack_data(unpacked_data, buf_load + packed_data_start, eh->dest_len * 16, packed_data_len);
    /* EXEPACK use backward processing */
    reverse(unpacked_data, eh->dest_len * 16);
    printf("UNPACKED\n");
    craftexec(buf_load, dh, eh, unpacked_data);
    free(unpacked_data);
}

int test_dos_header(struct dos_header *dh)
{
    /* at least one page */
    if (dh->e_cp == 0) {
        return 0;
    }
    /* last page must not hold 0 bytes */
    if (dh->e_cblp == 0) {
        return 0;
    }
    /* not even number of paragraphs */
    if (dh->e_cparhdr % 2 != 0) {
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    int fd;
    struct stat st;
    unsigned char *buf_load = NULL;
    struct dos_header *dh = NULL;

    if (argc != 2) {
        fprintf(stderr, "%s <EXEPACK_file>; ouput file is \"unpacked\"\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    fd = open(argv[1], O_RDONLY | O_BINARY);
    if (fd == -1) {
        perror("open()");
        exit(EXIT_FAILURE);
    }
    if (fstat(fd, &st) == -1) {
        perror("fstat()");
        exit(EXIT_FAILURE);
    }
    printf("SizeFile = %X\n", st.st_size);
    if ((buf_load = malloc(sizeof (char) * st.st_size)) == NULL) {
        perror("malloc()");
        exit(EXIT_FAILURE);
    }
    if (read(fd, buf_load, st.st_size) != st.st_size) {
        perror("read()");
        goto clean;
    }
    dh = (struct dos_header*)buf_load;
    if (dh->e_magic != 0x5A4D && !test_dos_header(dh)) {
        fprintf(stderr, "%s is not a valid MS-DOS executable\n", "LOAD.EXE");
        goto clean;
    }
    unpack(buf_load, dh);
clean:
    free(buf_load);
    close(fd);
    return 0;
}

void hex_dump(void *data, int size)
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