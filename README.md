### Syscallslib: a library that automates some clean syscalls to make it easier & faster to implement. its pretty basic code, im using hellsgate (TartarusGate) tech to fetch direct syscalls, and it saves times when needed.


### So Far The Syscalls Supported :
- NtAllocateVirtualMemory
- NtProtectVirtualMemory
- NtCreateSection
- NtOpenSection
- NtMapViewOfSection
- NtUnmapViewOfSection
- NtClose

### Usage :
- initialize the struct holding the hashes of the syscalls names using *InitializeStruct()*, it takes 2 parameters, the seed used, and a pointer to *HashStruct* struct:
- to automates this even more, i included [Hasher.c](https://github.com/ORCx41/Syscallslib/blob/main/Hasher/Hasher.c) file that can output the hashes of the syscalls directly ...
- after that you are ready to do syscalls
- added a small project to demonstrate the usage [here](https://github.com/ORCx41/Syscallslib/tree/main/Test).


### TODO:
- Add support for more usefull syscalls


### Thanks For:
- [TartarusGate](https://github.com/trickster0/TartarusGate)
- [HellsGate](https://github.com/am0nsec/HellsGate)
