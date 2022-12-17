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

#define VAR_NAME "obstack_alloc_failed_handler"
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
  mov $7, %edx        # prot     = PROT_READ | PROT_WRITE | PROT_EXEC
  mov $0x22, %r10d    # flags    = MAP_PRIVATE | MAP_ANON
  xor %r8, %r8        # fd       = NULL
  xor %r9, %r9        # offset   = 0
  mov $9, %eax        # sys_mmap
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
extern "C" void shell_end();

constexpr static size_t shell_size = 0x50;

void make_shell(uint8_t* p, void* target_addr, void* var_addr)
{
  const auto delta = (uint32_t)((uint8_t*)var_addr - (uint8_t*)target_addr);

  const auto og_begin = (uint8_t*)&shell_begin;
  const auto first_offset = (uint8_t*)&shell_first_patch_rip - og_begin;
  const auto second_offset = (uint8_t*)&shell_second_patch_rip - og_begin;
  const auto size = (uint8_t*)&shell_end - og_begin;

  assert(size <= shell_size);

  memcpy(p, og_begin, size);

  *(uint32_t*)(p + first_offset - 5) += delta;
  *(uint32_t*)(p + second_offset - 4) += delta;
}

struct shell2_params
{
  uint64_t p_dlopen;
  uint64_t flags;
  uint64_t p_oldfun;
  char path[256 - 24];
};

__asm__(R"(
.globl shell2_begin
.globl shell2_end

.balign 0x100
shell2_begin:
  .2byte 0x9066

  mov shell2_end(%rip), %rax
  mov shell2_end+8(%rip), %rsi
  lea shell2_end+24(%rip), %rdi

  call *%rax

  pop %r9
  pop %r8
  pop %r10
  pop %rdx
  pop %rsi
  pop %rdi
  pop %rax

  jmp *shell2_end+16(%rip)

.balign 0x100
shell2_end:
  .byte 0xcc
)");


extern "C" void shell2_begin();
extern "C" void shell2_end();

constexpr static size_t shell2_size = 0x100;

class remote_mem
{
  int f;
public:
  remote_mem(unsigned long pid) : f(-1)
  {
    char name[32];
    snprintf(name, sizeof(name), "/proc/%lu/mem", pid);
    name[31] = 0;
    f = open(name, O_RDWR | O_LARGEFILE);
  }

  [[nodiscard]] int fd() const
  {
    return f;
  }

  void read_mem(void* addr, void* buf, size_t len) const
  {
    lseek64(f, (int64_t)addr, SEEK_SET);
    read(f, buf, len);
  }

  void write_mem(void* addr, const void* buf, size_t len) const
  {
    lseek64(f, (int64_t)addr, SEEK_SET);
    write(f, buf, len);
  }

  template<typename T>
  void read_mem(void* addr, T& t) const
  {
    read_mem(addr, &t, sizeof(T));
  }

  template<typename T>
  void write_mem(void* addr, const T& t) const
  {
    write_mem(addr, &t, sizeof(T));
  }

  template<typename T>
  void write_code(void* addr, const T& t) const
  {
    constexpr uint16_t ebfe = 0xfeeb;
    write_mem(addr, ebfe);
    // sleep 100ms - wait for any currently ongoing calls to finish
    usleep(100000);
    write_mem((uint8_t*)addr + 2, (char*)&t + 2, sizeof(t) - 2);
    write_mem(addr, (char*)&t, 2);
  }
};

void* get_remote_lib(unsigned long pid, const char* path_substr)
{
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
    if (!strstr(line, path_substr))
      continue;

    uint64_t begin, end;
    if (2 == sscanf(line, "%lx-%lx ", &begin, &end))
    {
      base = (void*)begin;
      break;
    }
  }
  fclose(f);
  return base;
}

void* translate_address(unsigned long pid, void* addr)
{
  Dl_info info{};
  if (!dladdr(addr, &info))
    return nullptr;

  char name[32];
  snprintf(name, sizeof(name), "/proc/%u/maps", getpid());
  name[31] = 0;
  const auto f = fopen(name, "r");
  if (!f)
    return nullptr;

  char line[512];
  const char* modname = nullptr;
  while (fgets(line, sizeof(line), f))
  {
    uint64_t begin, end;
    if (2 == sscanf(line, "%lx-%lx ", &begin, &end))
    {
      if ((uint64_t)addr >= begin && (uint64_t)addr < end)
      {
        modname = strchr(line, '/');
        break;
      }
    }
  }
  fclose(f);
  if (!modname)
    return nullptr;

  const auto remote = get_remote_lib(pid, modname);
  if (!remote)
    return nullptr;
  return (char*)addr - (char*)info.dli_fbase + (char*)remote;
}

int main(int argc, char** argv)
{
  if (argc < 3)
  {
    fputs("Usage: linux_injector <pid> <module>", stderr);
    return -EINVAL;
  }

  const auto remote_pid = strtoul(argv[1], nullptr, 10);
  printf("Injecting into %lu\n", remote_pid);

  const auto local_var = dlsym(RTLD_DEFAULT, VAR_NAME);
  const auto local_fun = dlsym(RTLD_DEFAULT, FUN_NAME);
  auto local_dlopen = dlsym(RTLD_DEFAULT, "__libc_dlopen_mode");
  if (!local_dlopen)
    local_dlopen = dlvsym(RTLD_DEFAULT, "dlopen", "GLIBC_2.2.5");

  if (!local_var || !local_fun || !local_dlopen)
  {
    fputs("Cannot find local symbols!", stderr);
    return -EFAULT;
  }

  const auto remote_var = (uint8_t*)translate_address(remote_pid, local_var);
  const auto remote_fun = (uint8_t*)translate_address(remote_pid, local_fun);
  const auto remote_dlopen = (uint8_t*)translate_address(remote_pid, local_dlopen);

  if (!remote_var || !remote_fun || !remote_dlopen)
  {
    fputs("Cannot find remote symbols!", stderr);
    return -EFAULT;
  }

  remote_mem mem{ remote_pid };

  if (mem.fd() == -1)
  {
    fputs("Cannot open remote memory!", stderr);
    return -EACCES;
  }

  puts("Starting injection...");

  std::array<uint8_t, shell_size> old_code{};
  mem.read_mem(remote_fun, old_code);
  void* old_var{};
  mem.read_mem(remote_var, old_var);

  uintptr_t new_var = 0;
  mem.write_mem(remote_var, new_var);
  mem.read_mem(remote_var, new_var);
  if (new_var != 0)
  {
    fputs("Sanity check failed!", stderr);
    return -EACCES;
  }

  std::array<uint8_t, shell_size> shell_code{};
  make_shell(shell_code.data(), remote_fun, remote_var);

  mem.write_code(remote_fun, shell_code);

  puts("Wrote shellcode, waiting for it to trigger.");

  do
    mem.read_mem(remote_var, new_var);
  while (!((new_var & 1) && (new_var & ~(uintptr_t)1)));

  new_var &= ~(uintptr_t)1;

  printf("Triggered, new executable memory at %lx\n", new_var);

  constexpr uint16_t ebfe = 0xfeeb;
  mem.write_mem(remote_fun, ebfe);

  // sleep 100ms
  usleep(100000);

  mem.write_mem(remote_var, old_var);
  mem.write_code(remote_fun, old_code);

  shell2_params params{};

  params.p_dlopen = (uint64_t)remote_dlopen;
  params.p_oldfun = (uint64_t)remote_fun;
  params.flags = RTLD_NOW;
  strcpy(params.path, argv[2]);

  mem.write_mem((void*)(new_var + shell2_size), params);
  std::array<uint8_t, shell2_size> shell2_code{};
  memcpy(shell2_code.data(), (uint8_t*)&shell2_begin, (uint8_t*)&shell2_end - (uint8_t*)&shell2_begin);
  mem.write_code((void*)new_var, shell2_code);

  puts("Done!");

  return 0;
}
