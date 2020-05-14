// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/env.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line
#define	BOOTSTACKTOP 0xf0100000

struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display information about the stack", mon_backtrace },
	{ "showmappings", "Display physical page mappings that apply to addresses requested", mon_showmappings },
	{ "modifyperm", "Set, clear, or change the permissions of any mapping in the current address space", mon_modifyperm },
	{ "content", "Dump the contents of a range of memory given either a virtual or physical address", mon_content },
	{ "c", "continue", mon_continue },
	{ "si", "step", mon_step },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t* ebp = (uint32_t*)read_ebp(); 
	uint32_t eip;
	struct Eipdebuginfo info;

	cprintf("Stack backtrace:\n");
	while (ebp != 0x0) {
		eip = *(ebp+1);

		cprintf("ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n", 
			ebp, eip, *(ebp+2), *(ebp+3), *(ebp+4), *(ebp+5), *(ebp+6));

		if (debuginfo_eip(eip, &info) < 0){
			//command not found
			return -1;
		}
		uintptr_t offset = eip - info.eip_fn_addr;
		cprintf("\t%s:%d: %.*s+%d\n", info.eip_file, info.eip_line, info.eip_fn_namelen, info.eip_fn_name, offset);
		ebp = (uint32_t*)*ebp;
	}
	
	return 0;

}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	uintptr_t start;
	uintptr_t end;
	if (argc < 3){
		cprintf("Not enough arguments\n");
		return 0;
	}
	if (!(start = strtol(argv[1], NULL, 16)) ||
		!(end = strtol(argv[2], NULL, 16)) ||
		start > end){
		cprintf("Ilegall range\n");
		return 0;
	}

	pde_t *pgdir = KADDR(rcr3());

	cprintf("virtual addr             frame addr        permissions\n");
	for (; start < end; start += PGSIZE){
		pte_t *pte = pgdir_walk(pgdir, (void*)start, false);

		if (pte && (*pte & PTE_P)){
			cprintf("0x%x\t 0x%x\t\t", start, PTE_ADDR(*pte));
			if (*pte & PTE_P) cprintf("PTE_P ");
			if (*pte & PTE_W) cprintf("PTE_W ");
			if (*pte & PTE_U) cprintf("PTE_U ");
			cprintf("\n");
		} else {
			cprintf("0x%x\t Page unmapped\n", start);
		}
	}

	return 0;
}

int
extract_perm(char *perms, int *perm)
{
	while(*perms){ 
		switch (*perms){
			case 'w':
				*perm |= PTE_W;
				break;
			case 'u':
				*perm |= PTE_U;
				break;
			default:				
				return -1;
		}
		perms++;
	}
	return 0;
}

int
clearperm(uintptr_t va)
{
	pde_t *pgdir = KADDR(rcr3());
	pte_t *pte = pgdir_walk(pgdir, (void*)va, false);
	if (!pte){
		return -1;
	}
	if (*pte & PTE_P){
		*pte = PTE_ADDR(*pte) | PTE_P;
	} else {
		*pte = PTE_ADDR(*pte);
	}
	return 0;
}

int
setperm(uintptr_t va, int perm)
{
	clearperm(va);

	pde_t *pgdir = KADDR(rcr3());
	pte_t *pte = pgdir_walk(pgdir, (void*)va, false);
	if (!pte){
		return -1;
	}

	*pte |= perm;
	return 0;
}

int
changeperm(uintptr_t va, int perm)
{
	pde_t *pgdir = KADDR(rcr3());
	pte_t *pte = pgdir_walk(pgdir, (void*)va, false);
	if (!pte){
		return -1;
	}

	*pte ^= perm;
	return 0;
}

// modifyperm set/clear/change va perm= wup
int
mon_modifyperm(int argc, char **argv, struct Trapframe *tf)
{
	bool not_found = 0;
	if (argc < 3){
		cprintf("Not enough arguments\n");
		return 0;
	}

	uintptr_t va;
	if (!(va = strtol(argv[2], NULL, 16))){
		cprintf("Ilegall address\n");
		return 0;
	}

	int perm = 0x0;

	if (argc > 3){	
		if (extract_perm(argv[3], &perm) < 0){
			cprintf("Invalid permissions\n");
			return 0;
		}
	}


	switch (argv[1][0]){
		case 's':
			if (setperm(va, perm) < 0) not_found = 1;
			break;
		case 'c':
			if (argv[1][1] == 'l'){
				if (clearperm(va) < 0) not_found = 1;
			} else if (argv[1][1] == 'h'){
				if (changeperm(va, perm) < 0) not_found = 1;
			}
			break;
		default:
			cprintf("Not a valid command\n");
	}

	if (not_found) {
		cprintf("%x: Page not found\n", va);
	}
	return 0;
}	

// content v 0xf0000000 0xf0000010
//content v 0xf000cff8 0xf0010000
int
mon_content(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 4 ){
		cprintf("Invalid arguments\n");
		return 0;
	}

	char type = argv[1][0]; 
	if (type != 'v' && type != 'p'){
		cprintf("Invalid type");
		return 0;
	}
	
	uintptr_t start;
	uintptr_t end;
	uint32_t end_page = 0x0;
	uint32_t start_page = 0x0;

	if (!(start = strtol(argv[2], NULL, 16)) ||
	!(end = strtol(argv[3], NULL, 16)))
	{
		cprintf("Ilegall range\n");
		return 0;
	}

	if ((uint32_t)start > (uint32_t)end){
		return 0;
	}

	if (type == 'p'){
		for (; start < end; start += 4) {
	    	cprintf("pa: 0x%x\t va: 0x%x\t content:0x%x\n", start, start+KERNBASE, *(uintptr_t*)(start+KERNBASE));
	    }
		return 0;
	}

	pde_t *pgdir = KADDR(rcr3());

	for (; start < end; start += PGSIZE){
		pte_t *pte = pgdir_walk(pgdir, (void*)start, false);
		
		if (!pte){
			cprintf("%x: Page not found\n", start);
			return 0;
		}

		start_page = PGOFF(start);
		if ( PGNUM(start) == PGNUM(end)){
			end_page = PGOFF(end);
		} else {
			end_page = PGSIZE;
		}

		start = ROUNDDOWN(start, PGSIZE);

		for (; start_page < end_page; start_page += 4){
			cprintf("va:0x%x\t", (uint32_t)start + start_page); 
			cprintf("pa:0x%x\t", PTE_ADDR(*pte) + start_page);
			cprintf("content:0x%x\n", *(uintptr_t*)(start + start_page)); 
		}	
	}
	return 0;
}

int
mon_continue(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 1) {
		cprintf("invalid number of parameters\n");
		return 0;
	}
	if (tf == NULL) {
		cprintf("continue error.\n");
		return 0;
	}
	tf->tf_eflags &= ~FL_TF;
	env_run(curenv);
	return 0;
}

int
mon_step(int argc, char **argv, struct Trapframe *tf)
{
	if (argc != 1) {
		cprintf("invalid number of parameters\n");
		return 0;
	}
	if (tf == NULL) {
		cprintf("step error.\n");
		return 0;
	}
	tf->tf_eflags |= FL_TF;
	env_run(curenv);
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
