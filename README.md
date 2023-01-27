# linux_injector

A simple ptrace-less shared library injector for x64 Linux.

## Usage

`linux_injector <mode> <pid> <file>`

**mode**

1. normal dlopen
2. memfd + dlopen (for injecting into containers)
3. raw shellcode

**pid**

Target process id. Must have ptrace rights to it (required for accessing `/proc/$pid/mem`). Not ptraced, so another process can freely ptrace it.

**file**

For mode 1: Module to inject, will be `dlopen`ed in the remote process. Should probably be a full path, because the remote LD_LIBRARY_PATH is used otherwise for resolution.

For mode 2: Module to inject, will be `dlopen`ed in the remote process from a memfd, where the content will be copied.

For mode 3: Raw shellcode to inject. You will be mapped at a 16-aligned address, and start execution on a random hijacked thread. Place hooks or create a thread, then return.

## Modification

For control flow hijacking, this program needs a hijacking candidate. The code presented here uses `malloc`, this can be changed by editing `FUN_NAME` and recompiling. Make sure the hooked function can run under 100ms, so that it won't be overwritten while it executes. This means calls like `sleep` or `wait` are bad candidates for the initial shellcode. The function in question also needs to be more than `0x50` long for the shellcode not to overwrite other functions.

## Supported platforms

Glibc and musl are supported for the both the target and the source process. The target process can be running in a container, and can use a different libc. Modes 2 and 3 will not require any paths accessible to the target process.

Mode 2 requires Linux 3.17.

Tested on Oracle Linux 7 (mode 2 not supported), Fedora 37, and Alpine Linux 3.17

## License

[MIT License](LICENSE)
