struct Slot { unsigned char pad[32]; unsigned long long value; };
#pragma section(".data$AAA",read,write)
#pragma section(".data$BBB",read,write)
__declspec(allocate(".data$AAA")) unsigned char Prefix[4080]={1};
__declspec(allocate(".data$BBB")) struct Slot Block={{0},0x123456789abcdef0ULL};
