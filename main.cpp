//  Copyright (c) 2022 namazso <admin@namazso.eu>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <cstdint>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cerrno>

#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>

#include <array>
#include <elf.h>
#include <vector>
#include <fstream>
#include <sys/mman.h>
#include <sys/stat.h>

#define VAR_NAME "timezone"
#define FUN_NAME "malloc"

__asm__(R"(
.globl shell_begin
.globl shell_first_patch_rip
.globl shell_second_patch_rip
.globl shell_end

shell_begin:
  lock btsq $0, shell_begin(%rip)
shell_first_patch_rip: # actually for previous instruction
  jc shell_begin

  // push stuff to preserve
  push %rax
  push %rdi
  push %rsi
  push %rdx
  push %r10
  push %r8
  push %r9

  xor %edi, %edi      # addr     = 0
  mov $0x10000, %esi  # length   = 64k
shell_alloclen_patch_rip: # actually for previous instruction
  mov $7, %edx        # prot     = PROT_READ | PROT_WRITE | PROT_EXEC
  mov $0x22, %r10d    # flags    = MAP_PRIVATE | MAP_ANON
  xor %r8, %r8        # fd       = NULL
  xor %r9, %r9        # offset   = 0
  mov $9, %eax        # __NR_mmap
  syscall

  orb $1, %al         # keep other threads spinning
  mov %rax, shell_begin(%rip)  # store the allocation in our variable
shell_second_patch_rip: # actually for previous instruction

  xor %al, %al
  movw $0xfeeb, (%rax)
  jmp *%rax

shell_end:
  .byte 0xcc
)");

extern "C" void shell_begin();
extern "C" void shell_first_patch_rip();
extern "C" void shell_second_patch_rip();
extern "C" void shell_alloclen_patch_rip();
extern "C" void shell_end();

constexpr static size_t shell_size = 0x50;

void make_shell(uint8_t* p, void* target_addr, void* var_addr, int32_t alloclen)
{
  alloclen = (alloclen + 0x1000 - 1) / 0x1000 * 0x1000;

  const auto delta = (uint32_t)((uint8_t*)var_addr - (uint8_t*)target_addr);

  const auto og_begin = (uint8_t*)&shell_begin;
  const auto first_offset = (uint8_t*)&shell_first_patch_rip - og_begin;
  const auto second_offset = (uint8_t*)&shell_second_patch_rip - og_begin;
  const auto alloclen_offset = (uint8_t*)&shell_alloclen_patch_rip - og_begin;
  const auto size = (uint8_t*)&shell_end - og_begin;

  assert(size <= shell_size);

  memcpy(p, og_begin, size);

  *(uint32_t*)(p + first_offset - 5) += delta;
  *(uint32_t*)(p + second_offset - 4) += delta;
  *(int32_t*)(p + alloclen_offset - 4) = alloclen;
}

struct shell_raw_dlopen_params
{
  void* p_dlopen;
  void* p_oldfun;
  uint64_t flags;
};

__asm__(R"(

.struct 0
shell_raw_dlopen_params.p_dlopen:
.space 8
shell_raw_dlopen_params.p_oldfun:
.space 8
shell_raw_dlopen_params.flags:
.space 8
shell_raw_dlopen_params.path:


.text

.globl shell_raw_dlopen_begin
.globl shell_raw_dlopen_end

.balign 16

shell_raw_dlopen_begin:
  .2byte 0x9066

  mov shell_raw_dlopen_end+shell_raw_dlopen_params.flags(%rip), %rsi
  lea shell_raw_dlopen_end+shell_raw_dlopen_params.path(%rip), %rdi

  call *shell_raw_dlopen_end+shell_raw_dlopen_params.p_dlopen(%rip)

  pop %r9
  pop %r8
  pop %r10
  pop %rdx
  pop %rsi
  pop %rdi
  pop %rax

  jmp *shell_raw_dlopen_end+shell_raw_dlopen_params.p_oldfun(%rip)

.balign 16

shell_raw_dlopen_end:
  .byte 0xcc
)");


extern "C" void shell_raw_dlopen_begin();
extern "C" void shell_raw_dlopen_end();

struct shell_memfd_dlopen_params
{
  void* p_dlopen;
  void* p_sprintf;
  void* p_oldfun;
  uint64_t flags;
  uint64_t data_len;
};

__asm__(R"(
.globl shell_memfd_dlopen_begin
.globl shell_memfd_dlopen_end

.struct 0
shell_memfd_dlopen_params.p_dlopen:
.space 8
shell_memfd_dlopen_params.p_sprintf:
.space 8
shell_memfd_dlopen_params.p_oldfun:
.space 8
shell_memfd_dlopen_params.flags:
.space 8
shell_memfd_dlopen_params.data_len:
.space 8
shell_memfd_dlopen_params.data:


.text

.balign 16

shell_memfd_dlopen_begin:
  .2byte 0x9066

  push %rbx
  push %r12

  lea shell_memfd_null(%rip), %rdi  # name  = ""
  xor %esi, %esi                    # flags = 0
  mov $319, %eax                    # __NR_memfd_create

  syscall

  mov %rax, %rbx

  mov %rax, %rdi  # fd
  lea shell_memfd_dlopen_end+shell_memfd_dlopen_params.data(%rip), %rsi     # buf
  mov shell_memfd_dlopen_end+shell_memfd_dlopen_params.data_len(%rip), %rdx # count
  mov $1, %eax    # __NR_write

  syscall

  lea shell_memfd_format_out(%rip), %rdi  # str
  lea shell_memfd_format_str(%rip), %rsi  # format
  mov %rbx, %rdx                          # fd

  call *shell_memfd_dlopen_end+shell_memfd_dlopen_params.p_sprintf(%rip) # sprintf

  lea shell_memfd_format_out(%rip), %rdi # filename
  mov shell_memfd_dlopen_end+shell_memfd_dlopen_params.flags(%rip), %rsi # flag

  call *shell_memfd_dlopen_end+shell_memfd_dlopen_params.p_dlopen(%rip) # dlopen

  pop %r12
  pop %rbx

  pop %r9
  pop %r8
  pop %r10
  pop %rdx
  pop %rsi
  pop %rdi
  pop %rax

  jmp *shell_memfd_dlopen_end+shell_memfd_dlopen_params.p_oldfun(%rip)

shell_memfd_format_str:
  .ascii "/proc/self/fd/%lu"
shell_memfd_null:
  .byte 0
shell_memfd_format_out:
  .fill 32, 1, 0

.balign 16

shell_memfd_dlopen_end:
  .byte 0xcc
)");


extern "C" void shell_memfd_dlopen_begin();
extern "C" void shell_memfd_dlopen_end();

struct shell_raw_shellcode_params
{
  void* p_oldfun;
  uint64_t _padding;
};

__asm__(R"(
.globl shell_raw_shellcode_begin
.globl shell_raw_shellcode_end


.balign 16

shell_raw_shellcode_begin:
  .2byte 0x9066

  call shell_raw_shellcode_end+16

  pop %r9
  pop %r8
  pop %r10
  pop %rdx
  pop %rsi
  pop %rdi
  pop %rax

  jmp *shell_raw_shellcode_end(%rip)

.balign 16

shell_raw_shellcode_end:
  .byte 0xcc
)");


extern "C" void shell_raw_shellcode_begin();
extern "C" void shell_raw_shellcode_end();


class remote_mem
{
  int f;
public:
  explicit remote_mem(unsigned long pid) : f(-1)
  {
    char name[32];
    snprintf(name, sizeof(name), "/proc/%lu/mem", pid);
    name[31] = 0;
    f = open(name, O_RDWR | O_LARGEFILE);
  }

  ~remote_mem()
  {
    if (f != -1)
      close(f);
  }

  int fd() const
  {
    return f;
  }

  bool good() const
  {
    return f != -1;
  }

  ssize_t read_mem(void* addr, void* buf, size_t len) const
  {
    return pread(f, buf, len, (int64_t)addr);
  }

  ssize_t write_mem(void* addr, const void* buf, size_t len) const
  {
    return pwrite(f, buf, len, (int64_t)addr);
  }

  ssize_t write_code(void* addr, const void* buf, size_t len) const
  {
    if (len <= 2)
    {
      return write_mem(addr, buf, len);
    }
    constexpr uint16_t ebfe = 0xfeeb;
    if (!write_mem(addr, ebfe))
      return 0;
    // sleep 100ms - wait for any currently ongoing calls to finish
    usleep(100000);
    if (!write_mem((uint8_t*)addr + 2, (char*)buf + 2, len - 2))
      return 0;
    return write_mem(addr, (char*)buf, 2);
  }

  template<typename T>
  ssize_t read_mem(void* addr, T& t) const
  {
    return read_mem(addr, &t, sizeof(T));
  }

  template<typename T>
  ssize_t write_mem(void* addr, const T& t) const
  {
    return write_mem(addr, &t, sizeof(T));
  }

  template<typename T>
  ssize_t write_code(void* addr, const T& t) const
  {
    return write_code(addr, &t, sizeof(T));
  }
};


void* remote_dlsym(remote_mem& mem, void* elf, const char* name)
{
  Elf64_Ehdr elfh{};
  if (!mem.read_mem(elf, elfh))
    return nullptr;
  if (0 != memcmp(elfh.e_ident, ELFMAG, SELFMAG))
  {
    return nullptr;
  }
  size_t dynrva = 0;
  size_t dynvsz = 0;
  for (size_t i = 0; i < elfh.e_phnum; ++i)
  {
    Elf64_Phdr phdr{};
    if (!mem.read_mem((char*)elf + elfh.e_phoff + i * elfh.e_phentsize, phdr))
      return nullptr;
    if (phdr.p_type != PT_DYNAMIC)
      continue;
    dynrva = phdr.p_vaddr;
    dynvsz = phdr.p_memsz;
  }
  if (!dynrva || !dynvsz)
    return nullptr;
  uintptr_t symtab = 0;
  uintptr_t strtab = 0;
  uintptr_t syment = 0;
  for (size_t i = 0; i < dynvsz; i += sizeof(Elf64_Dyn))
  {
    Elf64_Dyn dyn{};
    if (!mem.read_mem((char*)elf + dynrva + i, dyn))
      return nullptr;
    if (dyn.d_tag == DT_STRTAB)
      strtab = dyn.d_un.d_ptr;
    if (dyn.d_tag == DT_SYMTAB)
      symtab = dyn.d_un.d_ptr;
    if (dyn.d_tag == DT_SYMENT)
      syment = dyn.d_un.d_val;
  }
  if (!symtab || !strtab || !syment)
    return nullptr;

  // this is actually incorrect
  if (symtab < (uintptr_t)elf)
    symtab += (uintptr_t)elf;
  if (strtab < (uintptr_t)elf)
    strtab += (uintptr_t)elf;

  char namecpy[256];
  const auto namebuflen = std::min(strlen(name) + 1, (size_t)256);

  for (size_t i = symtab; i < strtab; i += syment)
  {
    Elf64_Sym sym{};
    if (!mem.read_mem((void*)i, sym))
      return nullptr;
    if (!sym.st_name || !sym.st_value)
      continue;
    if (!mem.read_mem((char*)strtab + sym.st_name, namecpy, namebuflen))
      continue;
    namecpy[255] = 0;
    if (0 == strcmp(namecpy, name))
      return (char*)elf + sym.st_value;
  }
  return nullptr;
}

struct libc_syms
{
  void* var; // VAR_NAME
  void* fun; // FUN_NAME
  void* p_dlopen;
  void* p_sprintf;
};

bool is_remote_libc(remote_mem& mem, void* maybe_libc, libc_syms& out)
{
  libc_syms syms{};
  syms.var = remote_dlsym(mem, maybe_libc, VAR_NAME);
  if (!syms.var)
    return false;
  syms.fun = remote_dlsym(mem, maybe_libc, FUN_NAME);
  if (!syms.fun)
    return false;
  syms.p_dlopen = remote_dlsym(mem, maybe_libc, "dlopen");
  if (!syms.p_dlopen)
    syms.p_dlopen = remote_dlsym(mem, maybe_libc, "__libc_dlopen_mode");
  if (!syms.p_dlopen)
    return false;
  syms.p_sprintf = remote_dlsym(mem, maybe_libc, "sprintf");
  if (!syms.p_sprintf)
    return false;
  out = syms;
  return true;
}


void* get_remote_libc(remote_mem& mem, unsigned long pid, libc_syms& syms)
{
  syms = {};
  char name[32];
  snprintf(name, sizeof(name), "/proc/%lu/maps", pid);
  name[31] = 0;
  const auto f = fopen(name, "r");
  if (!f)
    return nullptr;

  char line[512];
  void* base = nullptr;
  while (fgets(line, sizeof(line), f))
  {
    uint64_t begin, end;
    if (2 != sscanf(line, "%lx-%lx ", &begin, &end))
      continue;
    if (is_remote_libc(mem, (void*)begin, syms))
    {
      base = (void*)begin;
      break;
    }
  }
  fclose(f);
  return base;
}

static std::pair<const void*, size_t> map_file_for_read(const char* path)
{
  const auto fd = open(path, O_RDONLY);
  if (fd == -1)
    return {};
  struct stat statbuf{};
  if (-1 == fstat(fd, &statbuf))
    return {};
  const auto p = mmap(nullptr, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if ((void*)-1 == p)
    return {};
  return { p, statbuf.st_size };
}

std::pair<const uint8_t*, size_t> make_shell_2(unsigned long mode, const char* module, const libc_syms& syms)
{
  size_t size;
  uint8_t* ptr;
  if (mode == 1)
  {

    shell_raw_dlopen_params p{};
    p.p_dlopen = syms.p_dlopen;
    p.p_oldfun = syms.fun;
    p.flags = RTLD_NOW;

    const auto size_shell = (uint8_t*)&shell_raw_dlopen_end - (uint8_t*)&shell_raw_dlopen_begin;
    const auto size_params = sizeof(shell_raw_dlopen_params);
    const auto size_data = strlen(module) + 1;
    size = size_shell + size_params + size_data;
    ptr = (uint8_t*)malloc(size);
    memcpy(ptr, (uint8_t*)&shell_raw_dlopen_begin, size_shell);
    memcpy(ptr + size_shell, &p, size_params);
    memcpy(ptr + size_shell + size_params, module, size_data);
  }
  else if (mode == 2)
  {
    const auto file = map_file_for_read(module);
    if (!file.first)
    {
      printf("Invalid file: %d\n", errno);
      exit(-EINVAL);
    }

    shell_memfd_dlopen_params p{};
    p.p_dlopen = syms.p_dlopen;
    p.p_oldfun = syms.fun;
    p.p_sprintf = syms.p_sprintf;
    p.flags = RTLD_NOW;
    p.data_len = file.second;

    const auto size_shell = (uint8_t*)&shell_memfd_dlopen_end - (uint8_t*)&shell_memfd_dlopen_begin;
    const auto size_params = sizeof(shell_memfd_dlopen_params);
    const auto size_data = file.second;
    size = size_shell + size_params + size_data;
    ptr = (uint8_t*)malloc(size);
    memcpy(ptr, (uint8_t*)&shell_memfd_dlopen_begin, size_shell);
    memcpy(ptr + size_shell, &p, size_params);
    memcpy(ptr + size_shell + size_params, file.first, size_data);
  }
  else if (mode == 3)
  {
    const auto file = map_file_for_read(module);
    if (!file.first)
    {
      printf("Invalid file: %d\n", errno);
      exit(-EINVAL);
    }

    shell_raw_shellcode_params p{};
    p.p_oldfun = syms.fun;

    const auto size_shell = (uint8_t*)&shell_raw_shellcode_end - (uint8_t*)&shell_raw_shellcode_begin;
    const auto size_params = sizeof(shell_raw_shellcode_params);
    const auto size_data = file.second;
    size = size_shell + size_params + size_data;
    ptr = (uint8_t*)malloc(size);
    memcpy(ptr, (uint8_t*)&shell_raw_shellcode_begin, size_shell);
    memcpy(ptr + size_shell, &p, size_params);
    memcpy(ptr + size_shell + size_params, file.first, size_data);
  }
  else
  {
    puts("Invalid mode");
    exit(-EINVAL);
  }
  return { ptr, size };
}

int main(int argc, char** argv)
{
  if (argc < 4)
  {
    fputs("Usage: linux_injector <mode> <pid> <file>\n", stderr);
    fputs("  Mode 1: normal dlopen\n", stderr);
    fputs("  Mode 2: memfd + dlopen (for injecting into containers)\n", stderr);
    fputs("  Mode 3: raw shellcode\n", stderr);
    return -EINVAL;
  }

  const auto mode = strtoul(argv[1], nullptr, 10);
  const auto remote_pid = strtoul(argv[2], nullptr, 10);
  const auto file = argv[3];
  printf("Injecting into %lu\n", remote_pid);

  remote_mem mem{ remote_pid };

  if (!mem.good())
  {
    fputs("Cannot open remote memory!\n", stderr);
    return -EACCES;
  }

  libc_syms syms{};
  const auto libc = get_remote_libc(mem, remote_pid, syms);
  if (!libc)
  {
    fputs("Cannot find suitable remote libc!\n", stderr);
    return -EFAULT;
  }

  const auto shell_2 = make_shell_2(mode, file, syms);

  printf("Remote libc: %p. Starting injection...\n", libc);

  std::array<uint8_t, shell_size> old_code{};
  mem.read_mem(syms.fun, old_code);
  void* old_var{};
  mem.read_mem(syms.var, old_var);

  uintptr_t new_var = 0;
  mem.write_mem(syms.var, new_var);
  mem.read_mem(syms.var, new_var);
  if (new_var != 0)
  {
    fputs("Sanity check failed!\n", stderr);
    return -EACCES;
  }

  std::array<uint8_t, shell_size> shell_code{};
  make_shell(shell_code.data(), syms.fun, syms.var, (int32_t)shell_2.second);

  mem.write_code(syms.fun, shell_code);

  puts("Wrote shellcode, waiting for it to trigger.");

  do
    mem.read_mem(syms.var, new_var);
  while (!((new_var & 1) && (new_var & ~(uintptr_t)1)));

  new_var &= ~(uintptr_t)1;

  printf("Triggered, new executable memory at %lx\n", new_var);

  constexpr uint16_t ebfe = 0xfeeb;
  mem.write_mem(syms.fun, ebfe);

  // sleep 100ms
  usleep(100000);

  mem.write_mem(syms.var, old_var);
  mem.write_code(syms.fun, old_code);

  mem.write_code((void*)new_var, shell_2.first, shell_2.second);

  puts("Done!");

  return 0;
}
