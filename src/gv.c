#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/mman.h>
#include <func.h>

#include "pgtable.h"

/* intel manual: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html */
/*
  sepefic program, so
	1. doesn't need to judge if little-endian or not
	2. use structure of 64 bits directly
*/

#define DEBUG 0

#define bool char
#define true 1
#define false 0

#define ALIGN_UP(x, a) (((x) + (a)-1) & ~((a)-1))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define FAILURE_EXIT(cond, func)            \
	do {                                \
		if (unlikely(cond)) {       \
			perror(func);       \
			exit(EXIT_FAILURE); \
		}                           \
	} while (0)

#define pr_dbg(fmt, args...)                 \
	{                                    \
		if (DEBUG) {                 \
			printf(fmt, ##args); \
		}                            \
	}

struct note_map {
	char *key;
	char *value;
};

static char* vmcore_filename = NULL;
static int fd = -1;

static bool pgd_present = true;
static bool pud_present = true;
static bool pmd_present = true;

static bool is_huge_page_1G = false;
static bool is_huge_page_2M = false;

static Elf64_Ehdr *elf_header = NULL;
static Elf64_Phdr **p_headers = NULL; // program headers
static Elf64_Nhdr *n_headers = NULL; // note header
static char *vmcoreinfo_desc = NULL;
static unsigned long vmcoreinfo_size = 0;
struct note_map *note_map = NULL;

static char *elf_type_to_str(uint16_t type)
{
	switch (type) {
	case ET_REL:
		return "REL";
	case ET_EXEC:
		return "EXEC";
	case ET_DYN:
		return "dynamic";
	case ET_CORE:
		return "core";
	default:
		return "unknown";
	}
}

static char *program_header_to_str(uint32_t type)
{
	switch (type) {
	case PT_NULL:
		return "NULL";
	case PT_LOAD:
		return "LOAD";
	case PT_DYNAMIC:
		return "DYNAMIC";
	case PT_INTERP:
		return "INTERP";
	case PT_NOTE:
		return "NOTE";
	case PT_SHLIB:
		return "SHLIB";
	case PT_PHDR:
		return "PWDR";
	case PT_GNU_STACK:
		return "STACK";
	default:
		return "processor-specific";
	}
}

static char *note_type_to_str(Elf64_Word type)
{
	switch (type) {
	case NT_PRSTATUS:
		return "prstatus struct";
	case NT_FPREGSET:
		return "fpregset struct";
	case NT_TASKSTRUCT:
		return "task structure";
	default:
		return "unknown type";
	}
}

static void print_header(char *type)
{
	printf("\n----------%s----------\n", type);
}

static void parse_elf_header()
{
	char *buf = malloc(sizeof(Elf64_Ehdr));
	int i = 0;

	FAILURE_EXIT(!buf, "malloc");
	/* read elf header into memory */
	read(fd, buf, sizeof(Elf64_Ehdr));
	elf_header = (Elf64_Ehdr *)buf;

	print_header("elf header");
	printf("MAGIC: ");
	for (i = 0; i < EI_NIDENT; ++i) {
		printf("%02x ", elf_header->e_ident[i]);
	}
	printf("\nTYPE: ");
	printf("%s\n", elf_type_to_str(elf_header->e_type));
	printf("program headers offset: %lu\n", elf_header->e_phoff);
}

static void open_elf()
{
	fd = open(vmcore_filename, O_RDWR);
	FAILURE_EXIT(fd == -1, "open");
}

static void dump_program_header(Elf64_Phdr *header)
{
	printf("type: %-10s", program_header_to_str(header->p_type));
	printf("offset: 0x%-14lx", header->p_offset);
	printf("filesize: 0x%-14lx", header->p_filesz);
	printf("vaddr: 0x%-20lx", header->p_vaddr);
	printf("paddr: 0x%lx\n", header->p_paddr);
}

static void parse_program_header()
{
	char **buf = malloc(elf_header->e_phnum * sizeof(void *));
	p_headers = malloc(elf_header->e_phnum * sizeof(void *));
	int i = 0;
	Elf64_Phdr *header = NULL;

	print_header("program headers");

	FAILURE_EXIT(!buf || !p_headers, "malloc");
	FAILURE_EXIT(lseek(fd, elf_header->e_phoff, SEEK_SET) == -1, "lseek");

	printf("COUNT: %u\n", elf_header->e_phnum);
	/* read program headers into memory */
	for (i = 0; i < elf_header->e_phnum; ++i) {
		buf[i] = malloc(elf_header->e_phentsize);
		FAILURE_EXIT(!buf[i], "malloc");
		read(fd, buf[i], elf_header->e_phentsize);
	}
	/* parse program header */
	for (i = 0; i < elf_header->e_phnum; ++i) {
		header = (Elf64_Phdr *)buf[i];
		p_headers[i] = (Elf64_Phdr *)buf[i];
		dump_program_header(header);
	}
}

static void parse_note_header()
{
	char *name_buf = NULL;
	char *desc_buf = NULL;
	char *ret_desc = NULL;
	int i = 0, rc = 0;
	Elf64_Phdr *p_header = NULL;

	print_header("note headers");

	for (i = 0; i < elf_header->e_phnum; ++i) {
		if (p_headers[i]->p_type == PT_NOTE)
			p_header = p_headers[i];
	}

	/* read note header into memory */
	FAILURE_EXIT(lseek(fd, p_header->p_offset, SEEK_SET) == -1, "lseek");
	n_headers = malloc(sizeof(Elf64_Nhdr));
	FAILURE_EXIT(!n_headers, "malloc");
	read(fd, n_headers, sizeof(*n_headers));

	FAILURE_EXIT(lseek(fd, p_header->p_offset + sizeof(*n_headers), SEEK_SET) == -1,
		     "lseek");
	while (1) {
		if (n_headers->n_namesz && n_headers->n_namesz) {
			/* read name into memory */
			name_buf = malloc(ALIGN_UP(n_headers->n_namesz, 4));
			desc_buf = malloc(ALIGN_UP(n_headers->n_descsz, 4));
			FAILURE_EXIT(!name_buf || !desc_buf, "malloc");

			read(fd, name_buf, ALIGN_UP(n_headers->n_namesz, 4));
			read(fd, desc_buf, ALIGN_UP(n_headers->n_descsz, 4));
			printf("name: %-10s desc_size: 0x%x type: %s\n", name_buf,
			       ALIGN_UP(n_headers->n_descsz, 4),
			       note_type_to_str(n_headers->n_type));
			if (strcmp(name_buf, "VMCOREINFO") == 0) {
				ret_desc = desc_buf;
				vmcoreinfo_size = ALIGN_UP(n_headers->n_descsz, 4);
				free(name_buf);
			} else {
				free(name_buf);
				free(desc_buf);
			}
			rc = read(fd, n_headers, sizeof(*n_headers));
			if (rc == 0 || rc == EOF) {
				break;
			}
		} else {
			break;
		}
	}

	if (!ret_desc) {
		printf("!!!!WARNING!!!! don't found VMCOREINFO\n");
		exit(EXIT_FAILURE);
	}

	vmcoreinfo_desc = malloc(vmcoreinfo_size);
	FAILURE_EXIT(!vmcoreinfo_desc, "malloc");
	sprintf(vmcoreinfo_desc, "%s", ret_desc);

	free(n_headers);
	free(ret_desc);
}

static void parse_vmcoreinfo_desc()
{
	unsigned int i = 0;
	unsigned nr_map = 0;
	char *line = NULL, *s = NULL;

	print_header("vmcoreinfo");
	for (i = 0; i < vmcoreinfo_size; ++i) {
		char c = vmcoreinfo_desc[i];
		if (c == '\n') {
			++nr_map;
		}
	}

	note_map = malloc(nr_map * sizeof(struct note_map));
	FAILURE_EXIT(!note_map, "malloc");
	line = strtok(vmcoreinfo_desc, "\n");
	while (line != NULL) {
		int key_len, value_len;

		/* for example: OSRELEASE=5.13.0 */
		s = strchr(line, '=');
		s++; /* skip '=' */
		key_len = s - line - 1; /* skip '=' */
		value_len = line + strlen(line) - s;
		note_map->key = malloc(key_len + 1);
		note_map->value = malloc(value_len + 1);
		FAILURE_EXIT(!note_map->key || !note_map->value, "malloc");

		strncpy(note_map->key, line, key_len);
		strncpy(note_map->value, s, value_len);
		note_map->key[key_len] = '\0';
		note_map->value[value_len] = '\0';
		if (strcmp(note_map->key, "SYMBOL(swapper_pg_dir)") == 0) {
			pg_table->swapper_pg_dir = strtoul(note_map->value, NULL, 16);
		}
		if (strcmp(note_map->key, "KERNELOFFSET") == 0) {
			printf("%s: %s\n", note_map->key, note_map->value);
		}

		line = strtok(NULL, "\n");
	}

	free(vmcoreinfo_desc);
}

static void get_swapper_pg_dir()
{
	open_elf();
	parse_elf_header();
	parse_program_header();
	parse_note_header();
	parse_vmcoreinfo_desc();
}

static void pg_table_alloc()
{
	pg_table = malloc(sizeof(struct page_table));
	FAILURE_EXIT(!pg_table, "malloc");

	pg_table->pgd = malloc(sizeof(pgd_t) * PTRS_PER_X);
	pg_table->pud = malloc(sizeof(pud_t) * PTRS_PER_X);
	pg_table->pmd = malloc(sizeof(pmd_t) * PTRS_PER_X);
	pg_table->pte = malloc(sizeof(pte_t) * PTRS_PER_X);

	FAILURE_EXIT(!pg_table->pgd || !pg_table->pmd || !pg_table->pud || !pg_table->pte,
		     "malloc");
}

static unsigned long find_target_offset(unsigned long addr, bool is_paddr)
{
	int i = 0;
	Elf64_Phdr *header = NULL;
	unsigned long file_offset = 0;

	if (is_paddr) {
		for (i = 0; i < elf_header->e_phnum; ++i) {
			if (p_headers[i]->p_paddr <= addr &&
			    p_headers[i]->p_paddr + p_headers[i]->p_filesz > addr) {
				header = p_headers[i];
				file_offset = addr - header->p_paddr + header->p_offset;
				// dump_program_header(header);
			}
		}
	} else {
		for (i = 0; i < elf_header->e_phnum; ++i) {
			if (p_headers[i]->p_vaddr <= addr &&
			    p_headers[i]->p_vaddr + p_headers[i]->p_filesz > addr) {
				header = p_headers[i];
				file_offset = addr - header->p_vaddr + header->p_offset;
				// dump_program_header(header);
			}
		}
	}

	return file_offset;
}

static pgd_t *translate_pgd(unsigned long vaddr)
{
	pgd_t *pgd;

	pgd = pgd_offset(vaddr);
	if (!(pgd->pgd & PAGE_PRESENT)) {
		pr_dbg("pgd mapping not present\n");
		pgd_present = false;
		return 0;
	}

	/*
	 * mask flags in high bits 63:48
	 * see intel manual Table 4-15. Format of a PML4 Entry (PML4E) that References a Page-Directory-Pointer Table
	 */
	mask_high_flags(pgd->pgd);
	mask_low_flags(pgd->pgd);

	return pgd;
}

static pud_t *translate_pud(unsigned long vaddr, bool *finished)
{
	pud_t *pud;
	unsigned long paddr_offset;
	*finished = false;

	pud = pud_offset(vaddr);

	if (!(pud->pud) & PAGE_PRESENT) {
		pr_dbg("pud mapping not present\n");
		*finished = true;
		pud_present = false;
		return NULL;
	}
	if ((pud->pud) & PS) {
		pr_dbg("1G huge page\n");
		/*
		 * mask flags in high bits 63:48 and mask flags in low bits 29:0
		 * see Table 4-16. Format of a Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page
		*/
		mask_high_flags(pud->pud);
		mask_low_flags(pud->pud);
		paddr_offset = vaddr & ~PUD_MASK; // get offset within page
		pud->pud |= paddr_offset;
		pr_dbg("page paddr is %lx\n", pud->pud);
		*finished = true;
		is_huge_page_1G = true;
		return pud;
	}

	mask_high_flags(pud->pud);
	mask_low_flags(pud->pud);
	return pud;
}

/* pud = pud & ((1ULL << 52) - (1 << shift)); */

static pmd_t *translate_pmd(unsigned long vaddr, bool *finished)
{
	pmd_t *pmd;
	unsigned long paddr_offset;

	pmd = pmd_offset(vaddr);
	if (!(pmd->pmd & PAGE_PRESENT)) {
		pr_dbg("pmd mapping not present\n");
		*finished = true;
		pmd_present = false;
		return NULL;
	}
	if (pmd->pmd & (PS)) {
		pr_dbg("2M huge page\n");
		/*
		 * mask flags in high bits and low bits
		 * see Table 4-18. Format of a Page-Directory Entry that Maps a 2-MByte Page
		*/
		mask_high_flags(pmd->pmd);
		mask_low_flags(pmd->pmd);
		paddr_offset = vaddr & ~PMD_MASK; // get offset within this page
		pmd->pmd |= paddr_offset;
		*finished = true;
		is_huge_page_2M = true;
		return pmd;
	}

	mask_high_flags(pmd->pmd);
	mask_low_flags(pmd->pmd);
	return pmd;
}

static unsigned long translate_pte(unsigned long vaddr)
{
	pte_t *pte;
	unsigned long paddr_offset;

	pte = pte_offset(vaddr);
	if (!(pte->pte & PAGE_PRESENT)) {
		pr_dbg("pte mapping not present\n");
		return 0;
	}

	mask_high_flags(pte->pte);
	mask_low_flags(pte->pte);
	paddr_offset = vaddr & ~PAGE_MASK;
	pte->pte |= paddr_offset;

	return pte->pte;
}

static unsigned long vaddr2paddr(unsigned long vaddr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	char ptr_len = sizeof(void *);
	unsigned long file_offset;
	bool finished = false;

	file_offset = find_target_offset(pg_table->swapper_pg_dir, false);
	pread(fd, pg_table->pgd, ptr_len * PTRS_PER_X, file_offset);
	pgd = translate_pgd(vaddr);
	if (!pgd) {
		return 0;
	}

	file_offset = find_target_offset(pgd->pgd, true);
	pr_dbg("pgd is 0x%lx, offset in vmcore is 0x%lx\n", pgd->pgd, file_offset);
	pread(fd, pg_table->pud, ptr_len * PTRS_PER_X, file_offset);
	pud = translate_pud(vaddr, &finished);
	if (finished) {
		if (pud)
			return pud->pud; // huge page
		return 0; // not present
	}

	file_offset = find_target_offset(pud->pud, true);
	pr_dbg("pud is 0x%lx, offset in vmcore is 0x%lu\n", pud->pud, file_offset);
	pread(fd, pg_table->pmd, ptr_len * PTRS_PER_X, file_offset);
	pmd = translate_pmd(vaddr, &finished);
	if (finished) {
		if (pmd)
			return pmd->pmd; // huge page
		return 0; // not present
	}

	file_offset = find_target_offset(pmd->pmd, true);
	pr_dbg("pmd is 0x%lx, offset in vmcore is 0x%lx\n", pmd->pmd, file_offset);
	pread(fd, pg_table->pte, ptr_len * PTRS_PER_X, file_offset);
	return translate_pte(vaddr);
}

static unsigned long translate_vaddr(const unsigned long vaddr)
{
	unsigned long paddr;

	pgd_present = true;
	pud_present = true;
	pmd_present = true;
	is_huge_page_2M = false;
	is_huge_page_1G = false;

	pr_dbg("swapper_pg_dir: %16lx\n", pg_table->swapper_pg_dir);
	// printf("translating %lx\n", vaddr);
	paddr = vaddr2paddr(vaddr);
	if (!paddr) {
		pr_dbg("vaddr %lx convert to paddr failed\n", vaddr);
		return 0;
	}
	pr_dbg("vaddr 0x%lx======>paddr 0x%lx, offset 0x%lx\n", vaddr, paddr,
	       find_target_offset(paddr, true));
	return paddr;
}

static Elf64_Phdr *get_headers(unsigned *header_num)
{
	const unsigned long begin_vaddr = 0xffff800000000000;
	const unsigned long end_vaddr = 0xffffffffffffffff;
	unsigned long cur_vaddr = begin_vaddr;
	unsigned long paddr = 0;
	Elf64_Phdr *header = malloc(sizeof(Elf64_Phdr));
	Elf64_Phdr *p_headers = header;
	int phead_num = 1;

	FAILURE_EXIT(!header, "malloc");
	memset(header, 0, sizeof(Elf64_Phdr));

	for (cur_vaddr = begin_vaddr;
	     /* cur_vaddr will overflow to 0, so need cur_vaddr >= begin_vaddr  */
	     cur_vaddr <= end_vaddr && cur_vaddr >= begin_vaddr;) {
		unsigned long step = PAGE_SIZE;

		paddr = translate_vaddr(cur_vaddr);
		if (!paddr) {
			/* map failed */
			if (!pgd_present)
				step = 1ul << 39;
			else if (!pud_present)
				step = 1ul << 30;
			else if (!pmd_present)
				step = 1ul << 21;
			cur_vaddr += step;
			continue;
		}

		header->p_offset = find_target_offset(paddr, true);
		header->p_paddr = paddr;
		header->p_type = PT_LOAD;
		header->p_vaddr = cur_vaddr;
		header->p_flags = PF_X | PF_W | PF_R;
		if (is_huge_page_1G) {
			step = 1ul << 30;
		} else if (is_huge_page_2M) {
			step = 1ul << 21;
		}
		header->p_filesz = step;
		header->p_memsz = step;
		cur_vaddr += step;

		if (phead_num > 1) {
			/* try to merge */
			Elf64_Phdr *pre_header = header - 1;
			if (pre_header->p_offset + pre_header->p_filesz ==
				    header->p_offset &&
			    pre_header->p_paddr + pre_header->p_filesz ==
				    header->p_paddr &&
			    pre_header->p_vaddr + pre_header->p_filesz ==
				    header->p_vaddr) {
				pre_header->p_filesz += header->p_filesz;
				pre_header->p_memsz = pre_header->p_filesz;
				memset(header, 0, sizeof(*header));
				continue;
			}
		}

		phead_num++;
		header = realloc(p_headers, sizeof(Elf64_Phdr) * phead_num);
		p_headers = header;
		FAILURE_EXIT(!p_headers, "realloc");
		/* point to last header */
		header += (phead_num - 1);
		memset(header, 0, sizeof(Elf64_Phdr));
	}

	*header_num = phead_num;
	printf("get %u extra headers\n", phead_num);
	return p_headers;
}

static void __insert_pheaders(Elf64_Phdr *headers, unsigned num)
{
	int i = 0;
	struct stat stat_buf;
	int ret, all_ret = 0;
	Elf64_Shdr s_header = { 0 };

	FAILURE_EXIT(fstat(fd, &stat_buf), "stat");
	FAILURE_EXIT(lseek(fd, 0, SEEK_END) == -1, "lseek");

	for (i = 0; i < elf_header->e_phnum; ++i) {
		ret = write(fd, p_headers[i], sizeof(Elf64_Phdr));
		all_ret += ret;
	}
	ret = write(fd, headers, sizeof(Elf64_Phdr) * num);
	all_ret += ret;

	elf_header->e_shoff = stat_buf.st_size + all_ret;
	s_header.sh_info = elf_header->e_phnum + num;
	write(fd, &s_header, sizeof(s_header));

	FAILURE_EXIT(lseek(fd, 0, SEEK_SET) == -1, "lseek");
	elf_header->e_phoff = stat_buf.st_size;
	elf_header->e_phnum =
		num + elf_header->e_phnum > 0xffff ? 0xffff : num + elf_header->e_phnum;
	elf_header->e_shnum = 1;
	elf_header->e_shentsize = sizeof(s_header);
	write(fd, elf_header, sizeof(Elf64_Ehdr));
}

static void insert_pheaders()
{
	Elf64_Phdr *headers = NULL;
	unsigned pheaders_num = 0;

	headers = get_headers(&pheaders_num);
	__insert_pheaders(headers, pheaders_num);
}

int main(int argc, char **argv)
{
	if (DEBUG) {
		if (argc < 2) {
			printf("debugging mode, used to translate a vaddr to paddr\n");
			printf("USAGE: %s $vaddr\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	} else{
		if (argc < 2) {
			printf("USAGE: %s $vmcorepath\n", argv[0]);
			exit(EXIT_FAILURE);
		}
		vmcore_filename = argv[1];
	}

	pg_table_alloc();
	get_swapper_pg_dir();
	if (DEBUG) {
		translate_vaddr(strtoul(argv[1], NULL, 16));
	} else {
		insert_pheaders();
	}
	return 0;
}
