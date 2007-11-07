#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <rpm/rpmlib.h>

#define	RPM_LEAD_SIZE 96

struct rpm_lead {
	unsigned char magic[4];
	unsigned char major;
	unsigned char minor;
	short type;
	short archnum;
	char name[66];
	short osnum;
	short signature_type;
	char reserved[16];
};

struct rpm_header {
	unsigned char magic[4];
	unsigned char reserved[4];
	int nindex;
	int hsize;
};

struct rpm_header_index {
	int tag;
	int type;
	int offset;
	int count;
};

#define ALIGN(value, base) (((value) + (base - 1)) & ~((base) - 1))

static void dump_header(struct rpm_header *header)
{
	struct rpm_header_index *base, *index;
	int i, j, nindex, tag, offset, type, count;
	char *pool, *name;

	nindex = ntohl(header->nindex);
	printf("header index records: %d\n", nindex);
	printf("header storage size: %d\n", ntohl(header->hsize));
	base = (struct rpm_header_index *) (header + 1);
	pool = (void *) (header + 1) + nindex * sizeof *index;

	printf("headers:\n");
	for (i = 0; i < nindex; i++) {
		index = base + i;
		tag = ntohl(index->tag);
		offset = ntohl(index->offset);
		type = ntohl(index->type);
		count = ntohl(index->count);
		printf("  0x%08x 0x%08x 0x%08x 0x%08x\n",
		       tag, type, offset, count);

		switch (tag) {
		case RPMTAG_NAME:
			name = "name";
			break;
		case RPMTAG_VERSION:
			name = "version";
			break;
		case RPMTAG_RELEASE:
			name = "release";
			break;
		case RPMTAG_REQUIRENAME:
			name = "requires";
			break;
		default:
			name = "unknown";
			break;
		}

		switch (type) {
		case RPM_STRING_TYPE:
			printf("    (%s %s)\n", name, pool + offset);
			break;
		case RPM_STRING_ARRAY_TYPE:
			printf("    (%s", name);
			for (j = 0; j < count; j++) {
				printf(" %s", pool + offset);
				offset += strlen(pool + offset) + 1;
			}
			printf(")\n");
			break;
		}
	}
}

void
razor_rpm_dump(const char *filename)
{
	struct stat buf;
	void *p;
	int fd, nindex, hsize;
	struct rpm_header *signature, *header;
	struct rpm_header_index *index;

	if (stat(filename, &buf) < 0) {
		fprintf(stderr, "no such file %s\n", filename);
		return;
	}

	fd = open(filename, O_RDONLY);
	p = mmap(NULL, buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	printf("%s: %ldkB\n", filename, buf.st_size / 1024);
	signature = p + RPM_LEAD_SIZE;

	nindex = ntohl(signature->nindex);
	hsize = ntohl(signature->hsize);
	header = (void *) (signature + 1) +
		ALIGN(nindex * sizeof *index + hsize, 8);

	dump_header(signature);
	dump_header(header);

	munmap(p, buf.st_size);
}
