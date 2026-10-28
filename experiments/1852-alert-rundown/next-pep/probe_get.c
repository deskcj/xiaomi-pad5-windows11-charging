struct Slot { unsigned char pad[32]; unsigned long long value; };
extern struct Slot Block;
unsigned long long get_after(void) { return Block.value; }
unsigned long long get_zero(void) { return *(unsigned long long *)Block.pad; }
unsigned long long get_before(void) { return *(unsigned long long *)((unsigned char *)&Block-16); }
