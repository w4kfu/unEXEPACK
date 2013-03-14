#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

struct dos_header
{
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

struct exepack_header
{
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

void hex_dump(void *data, int size);

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

void reverse(char s[], size_t length)
{
	int c, i, j;

	for (i = 0, j = length - 1; i < j; i++, j--)
	{
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

void unpack_data(unsigned char *unpacked_data, unsigned char *buf, size_t unpacked_data_size, size_t packed_data_len)
{
	unsigned char opcode;
	unsigned short count;
	unsigned char fillbyte;
	unsigned char *save_buf = NULL;
	unsigned char *save_unp = NULL;

	save_buf = buf;
	save_unp = unpacked_data;
	while(*buf == 0xFF)
		buf++;
	while (1)
	{
		opcode = *buf++;
		count = *(buf) * 0x100 + *(buf + 1);
		buf += 2;
		if ((opcode & 0xFE) == 0xB0)
		{
			fillbyte = *buf++;
			memset(unpacked_data, fillbyte, count);
			unpacked_data += count;
		}
		else if ((opcode & 0xFE) == 0xB2)
		{
			memcpy(unpacked_data, buf, count);
			unpacked_data += count;
			buf += count;
		}
		else
		{
			fprintf(stderr, "WTF ?!\n");
			exit(0);
		}
		if ((opcode & 1) == 1)
			break;
	}
	if (buf - save_buf != packed_data_len)
	{
		if ((packed_data_len - (buf - save_buf)) > (unpacked_data_size - (unpacked_data - save_unp)))
		{
			fprintf(stderr, "HEU LOL WAT?!\n");
			exit(0);
		}
		printf("Left = %X\n", packed_data_len - (buf - save_buf));
		printf("Already copied = %X\n", unpacked_data - save_unp);
		memcpy(unpacked_data, buf, packed_data_len - (buf - save_buf));
	}
}

char *create_reloc_table(char *buf_load, struct dos_header *dh, struct exepack_header *eh, int *reloc_table_size)
{
	int reloc_length;
	int nb_reloc;
	char *buf_reloc = NULL;
	char *sbuf_reloc = NULL;
	char *reloc = NULL;
	int i, j;
	int nb_entry;
	int num_entry;

	reloc_length = eh->exepack_size - strlen("Packed file is corrupt") - sizeof (struct exepack_header) - 0x105; /* Unpacker Length */
	nb_reloc = (reloc_length - 16 * sizeof (unsigned short)) / 2;
	*reloc_table_size = nb_reloc * 2 * sizeof(unsigned short);
	printf("reloc_table_size = %d\n", *reloc_table_size);
	if (!(buf_reloc = malloc(sizeof (char) * *reloc_table_size)))
	{
		perror("malloc()");
		exit(0);
	}
	reloc = buf_load + ((dh->e_cparhdr + dh->e_cs) * 16 - (eh->skip_len - 1) * 16) + sizeof (struct exepack_header) + 0x105;
	if (strncmp(reloc, "Packed file is corrupt", strlen("Packed file is corrupt")))
	{
		fprintf(stderr, "hmm wat?\n");
		exit(0);
	}
	reloc += strlen("Packed file is corrupt");
	printf("OFFSET RELOC = %X\n", reloc - buf_load);
	*reloc_table_size = 0;
	sbuf_reloc = buf_reloc;
	for (i = 0; i < 16; i++)
	{
		nb_entry = *(unsigned short*)reloc;
		reloc += 2;
		if (nb_entry == 0)
			break;
		for (j = 0; j < nb_entry; j++)
		{
			num_entry = *(unsigned short*)reloc;
			reloc += 2;
			*(unsigned short*)(buf_reloc) = num_entry;
			buf_reloc += 2;
			*reloc_table_size += 2;
			*(unsigned short*)(buf_reloc) = i * 0x1000;
			buf_reloc +=2 ;
			*reloc_table_size += 2;
		}
	}
	printf("End reloc_table_size = %d\n", *reloc_table_size);
	printf("NB ENTRY = %d\n", *reloc_table_size / (2 * sizeof (unsigned short)));
	hex_dump(sbuf_reloc, *reloc_table_size);
	return sbuf_reloc;
}

void writeexe(struct dos_header *dhead, struct exepack_header *eh, char *unpacked_data, char *reloc, size_t reloc_size, size_t padding)
{
	int fd;
	int i;

	fd = open("out", O_WRONLY | O_CREAT);
	if (fd == -1)
	{
		perror("open()");
		exit(0);
	}
	write(fd, dhead, sizeof (struct dos_header));
	write(fd, reloc, reloc_size);
	for (i = 0; i < padding; i++)
		write(fd, "\x00", 1);
	write(fd, unpacked_data, eh->dest_len * 16);
	close(fd);
}

void craftexec(char *buf_load, struct dos_header *dh, struct exepack_header *eh, char *unpacked_data)
{
	struct dos_header dhead;
	int header_size;
	int total_length;
	int padding_length;
	int reloc_size;
	char *reloc = NULL;


	reloc = create_reloc_table(buf_load, dh, eh, &reloc_size);

	header_size = sizeof (struct dos_header) + reloc_size;

	memset(&dhead, 0, sizeof (struct dos_header));
	dhead.e_magic = 0x5A4D;
	dhead.e_cparhdr = header_size / 16;
	dhead.e_cparhdr = (dhead.e_cparhdr / 32 + 1) * 32;

	padding_length = dhead.e_cparhdr * 16 - header_size;
	total_length = header_size + padding_length + eh->dest_len * 16;

	printf("TOTAL_LENGTH = %d\n", total_length);
	dhead.e_ss = eh->real_ss;
	dhead.e_sp = eh->real_sp;
	dhead.e_ip = eh->real_ip;
	dhead.e_cs = eh->real_cs;

	dhead.e_minalloc = total_length / 60;
	dhead.e_maxalloc = 0xFFFF;

	dhead.e_lfarlc = sizeof (struct dos_header);
	dhead.e_crlc = reloc_size / (2 * sizeof (unsigned short));

	dhead.e_cblp = total_length % 512;
	dhead.e_cp = total_length / 512 + 1;
	print_dos_header(&dhead);
	writeexe(&dhead, eh, unpacked_data, reloc, reloc_size, padding_length);
}

void unpack(char *buf_load, struct dos_header *dh)
{
	int exepack_offset;
	struct exepack_header *eh;
	char *exepack_data = NULL;
	int packed_data_start;
	int packed_data_end;
	int packed_data_len;
	char *unpacked_data = NULL;

	exepack_offset = (dh->e_cparhdr + dh->e_cs) * 16;
	eh = (struct exepack_header*)(buf_load + exepack_offset);
	if (eh->signature != 0x4252)
	{
		fprintf(stderr, "This is not a valid exepack executable\n");
		return;
	}
	printf("Header exepack = %X\n", exepack_offset);
	exepack_data = buf_load + exepack_offset + sizeof (struct exepack_header);
	packed_data_start = dh->e_cparhdr * 16;
	packed_data_end = exepack_offset - (eh->skip_len - 1) * 16;
	packed_data_len = packed_data_end - packed_data_start;
	printf("PackedDataStart = %X\n", packed_data_start);
	printf("PackedDataEnd = %X\n", packed_data_end);
	printf("PackedDataLen = %X\n", packed_data_len);
	if (!(unpacked_data = malloc(sizeof (char) * (eh->dest_len) * 16)))
	{
		perror("malloc()");
		return;
	}
	printf("UnpackedDataLen = %X\n", eh->dest_len * 16);
	printf("OFFSET = %X\n", (buf_load + packed_data_end - 1) - buf_load);
	reverse(buf_load + packed_data_start, packed_data_len);
	//hex_dump(buf_load + packed_data_start, 0x100);
	unpack_data(unpacked_data, buf_load + packed_data_start, eh->dest_len * 16, packed_data_len);
	reverse(unpacked_data, eh->dest_len * 16);
	printf("UNPACKED\n");
	//hex_dump(unpacked_data, eh->dest_len * 16);
	craftexec(buf_load, dh, eh, unpacked_data);
	free(unpacked_data);
}

int test_dos_header(struct dos_header *dh)
{
	if (dh->e_cp == 0)
		return 0;
	if (dh->e_cblp == 0)
		return 0;
	if (dh->e_cparhdr % 2 != 0)
		return 0;
	if (dh->e_ovno != 0)
		return 0;
	if (dh->e_crlc != 0)
		return 0;
	return 1;
}

int main(void)
{
	int fd;
	struct stat st;
	char *buf_load = NULL;
	struct dos_header *dh = NULL;

	fd = open("LOAD.EXE", O_RDONLY);
	if (fd == -1)
	{
		perror("open()");
		exit(EXIT_FAILURE);
	}
	if (fstat(fd, &st) == -1)
	{
		perror("fstat()");
		exit(EXIT_FAILURE);
	}
	printf("SizeFile = %X\n", st.st_size);
	if ((buf_load = malloc(sizeof (char) * st.st_size)) == NULL)
	{
		perror("malloc()");
		exit(EXIT_FAILURE);
	}
	if (read(fd, buf_load, st.st_size) != st.st_size)
	{
		perror("read()");
		goto clean;
	}
	dh = (struct dos_header*)buf_load;
	if (dh->e_magic != 0x5A4D && !test_dos_header(dh))
	{
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

    for(n = 1; n <= size; n++)
    {
        if (n % 16 == 1)
        {
                snprintf(addrstr, sizeof(addrstr), "%.4x",
                    (p - (unsigned char*)data));
        }
        c = *p;
        if (isalnum(c) == 0)
        {
            c = '.';
        }
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);
        if (n % 16 == 0)
        {
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0)
        {
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }
    if (strlen(hexstr) > 0)
    {
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}
