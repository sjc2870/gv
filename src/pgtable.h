typedef struct {
	unsigned long pgd;
} pgd_t;

typedef struct {
	unsigned long pte;
} pte_t;

typedef struct {
	unsigned long pmd;
} pmd_t;

typedef struct {
	unsigned long pud;
} pud_t;

struct page_table {
	unsigned long swapper_pg_dir;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
};

static struct page_table *pg_table = NULL;

#define PAGE_SHIFT 12
#define PMD_SHIFT 21
#define PUD_SHIFT 30
#define PGDIR_SHIFT 39

#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PMD_SIZE (1UL << PMD_SHIFT)
#define PMD_MASK (~(PMD_SIZE-1))
#define PUD_SIZE (1UL << PUD_SHIFT)
#define PUD_MASK (~(PUD_SIZE - 1))
#define PGDIR_SIZE (1UL << PGDIR_SHIFT)
#define PGDIR_MASK (~(PGDIR_SIZE - 1))

/* means PTRS_PER_PGD PTRS_PER_PUD PTRS_PER_PMD */
static const int PTRS_PER_X = (PAGE_SIZE / sizeof(void *));

#define PAGE_BIT_PRESENT 0
#define PAGE_BIT_SIZE 7

#define PAGE_PRESENT (1 << PAGE_BIT_PRESENT)
#define PS ( 1 << PAGE_BIT_SIZE)

#define pgd_index(a) (((a) >> PGDIR_SHIFT) & (PTRS_PER_X - 1))
#define pud_index(a) (((a) >> PUD_SHIFT) & (PTRS_PER_X - 1))
#define pmd_index(a) (((a) >> PMD_SHIFT) & (PTRS_PER_X - 1))
#define pte_index(a) (((a) >> PAGE_SHIFT) & (PTRS_PER_X - 1))

#define pud_base(pgd) (pg_table->pud)
#define pmd_base(pud) (pg_table->pmd)
#define pte_base(pmd) (pg_table->pte)

#define pgd_offset(a) ((pg_table->pgd) + pgd_index(a))
#define pud_offset(a) ((pg_table->pud) + pud_index(a))
#define pmd_offset(a) ((pg_table->pmd) + pmd_index(a))
#define pte_offset(a) ((pg_table->pte) + pte_index(a))

#define mask_high_flags(paddr) ((paddr) &= ((1UL << 52) - 1))
#define mask_low_flags(paddr) ((paddr) &= PAGE_MASK)