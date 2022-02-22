# SharpHalos
SharpHalos is my implementation of Halo's Gate technique in C#. If you dont know what is Halo's Gate technique, you can take a look at [SEKTOR7's blog post](https://blog.sektor7.net/#!res/2021/halosgate.md) or you can read my kinda-crappy explanation. Halo's Gate is basically an evolution of Hell's Gate, which is a technique that tries to extract the syscall ID from a syscall stub, but the problem is that when the syscall stub is hooked, Hell's Gate cant extract the syscall ID, hence Halo's Gate. If Halo's Gate sees a hooked syscall stub, it will get the syscall ID from the neighbouring syscall stub, and then increment the syscall ID with the "distance" from the original syscall stub, if the neighbouring syscall stub is hooked, then it will check the next neighbouring syscall stub and so on.

# Usage Example
You can take a look at the [source code](https://github.com/GetRektBoy724/SharpHalos/blob/main/SharpHalos.cs#L641). For compilation, dont forget to add `unsafe` parameter ;)

# Sources 
- https://blog.sektor7.net/#!res/2021/halosgate.md
- https://www.crummie5.club/freshycalls/
- https://trickster0.github.io/posts/Halo%27s-Gate-Evolves-to-Tartarus-Gate/
- https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/
