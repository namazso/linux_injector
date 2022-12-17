# linux_injector

A simple ptrace-less shared library injector for x64 Linux.

## Usage

`linux_injector <pid> <module>`

**pid**

Target process id. Must have ptrace rights to it (required for accessing `/proc/$pid/mem`).

**module**

Module to inject, will be `dlopen`ed in the remote process. Should probably be a full path, because the remote LD_LIBRARY_PATH is used otherwise for resolution.

## Modification

For control flow hijacking, this program needs a hijacking candidate. The code presented here uses `malloc`, this can be changed by editing `FUN_NAME` and recompiling. Make sure the hooked function can run under 100ms, so that it won't be overwritten while it executes. This means calls like `sleep` or `wait` are bad candidates for the initial shellcode. The function in question also needs to be more than `0x50` long for the shellcode not to overwrite other functions.

## Shortcomings

The code expects that the target uses the same libc as available to us. If it does not, then the remote symbols won't be found. This could be fixed by reading the remote libraries and scanning for our symbols in them.

## Supported OS

Most Linuxes that use glibc should be supported. Tested only on Oracle Linux 8.7.

## License

[MIT License](LICENSE)
