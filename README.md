# Perun's Fart

This is my own implementation of the Perun's Fart Evasion technique by Sektor7. 

## About the technique

- It creates a process in a suspende state
- Reads the ntdll.dll of the process and copied the syscall stubs of the `Nt` APIs to `ntdll.dll` in the memory of the current process
- Since, initially when a process is created, the loader is not initialized, so there is no hooks injected in the memory of the created process
- So, when the process is in suspended state, only the `ntdll.dll` is loaded in memory, and then the `LdrpInitializeProcess` function is called, which initializes the execution environment. (https://stackoverflow.com/questions/30026604/why-does-process-loads-modulesdlls-in-different-phases)
- Also, the created process is a child process of our current process. Therefore, we can take the address of the `ntdll.dll` of the current process, and use this same address to read from the memory of the remote suspended process


### Changes I have tried to make

- Used `Ldr` structure to find the base address of `ntdll.dll`
- From the base address found the syscall stubs of all the `Nt` functions

## References 

1) https://blog.sektor7.net/#!res/2021/perunsfart.md
2) https://github.com/plackyhacker/Peruns-Fart
3) https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c
4) https://github.com/paranoidninja/PIC-Get-Privileges/blob/main/addresshunter.h
5) https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time


**Refer to my Blog post explaining this code : https://dosxuz.gitlab.io/post/perunsfart/**
