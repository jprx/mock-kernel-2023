# Mock Kernel
Mock Kernel was a UIUCTF 2023 capture-the-flag kernel exploitation challenge created by Joseph Ravichandran.

We rated this challenge as "extreme" difficulty. The challenge received 4 solves during the competition.

Participants are given ssh and vnc access to a Mac OS X Snow Leopard (10.6, `10A432`) virtual machine.
This VM is running a special kernel, with version string (`uname -v`): `sigpwny:xnu-1456.1.26/BUILD/obj//RELEASE_X86_64`.

## Challenge Description

```
We found my brother's old iMac but forgot the password,
maybe you can help me get in?

He said he was working on something involving "pointer
authentication codes" and "a custom kernel"? I can't recall...

Attached is the original Snow Leopard kernel macho as well
as the kernel running on the iMac.
```

There are two attached files- `mach_kernel.orig` and `mach_kernel.sigpwny`.
`mach_kernel.orig` is the original Snow Leopard kernel from 10.6 (`/mach_kernel`), and `mach_kernel.sigpwny` is the modified kernel running on the VM.

## Setting up a VM

To create a Snow Leopard virtual machine suitable for testing this challenge, follow these steps:

1. https://github.com/jprx/how-to-install-snow-leopard-in-qemu
1. Inside the VM, rename `/System/Library/Extensions/AppleProfileFamily.kext` to `AppleProfileFamily.kext.bak`.
1. Delete `/mach_kernel` and replace it with the attached `mach_kernel.sigpwny` file (saved as `/mach_kernel`).
1. Reboot the VM and then run `uname -v`, you should see the version string of `sigpwny:xnu-1456.1.2.6/BUILD/obj//RELEASE_X86_64`.
1. Install Xcode 3.2 (`xcode3210a432.dmg`) inside the VM to get `gcc`.

## Building `mach_kernel.sigpwny`

**NOTE**: You do not have to build the kernel to try the challenge, just use `mach_kernel.sigpwny` provided in the CTF files repo.
If you want to compile and install your own kernel in the VM though, here's how!

To compile XNU, follow the excellent instructions by Shantonu Sen [here](https://shantonu.blogspot.com/2009/09/).
You want to checkout `xnu-1456.1.26` from [the xnu repo](https://github.com/apple-oss-distributions/xnu).

You will want to build XNU inside of a Snow Leopard VM.
Before you can build XNU, you'll need Xcode 3.2 installed inside the virtual machine.
Several open source components should also be installed (follow the instructions posted above).
Finally, once the dependencies are installed, `git apply` the patches from this repository (in `patch_xnu-1456.1.26.diff`) to `xnu`.

Build xnu with `make ARCH_CONFIGS="X86_64" KERNEL_CONFIGS="RELEASE"`.
You should have a shiny new kernel located at `BUILD/obj/RELEASE_X86_64/mach_kernel` (and an unstripped kernel macho at `mach_kernel.sys` and `mach_kernel.sys.dSYM`, which can be useful for debugging).

Make sure to rename `AppleProfileFamily.kext` in `/System/Library/Extensions` to something other than a `.kext`, as this kext is incompatible with a user-compiled XNU kernel.
If you forget to do this, the kernel will panic on boot, and you'll have to recover the VM (either by editing the HFS filesystem from Linux if you disabled journaling, from a Mac, or by rebooting the install DVD and copying the old kernel over).
**Do this before copying the kernel to `/mach_kernel`**.

Copy the kernel to `/mach_kernel` and reboot the VM to reload the new kernel.
A new kernelcache will automatically be linked for you.

**Note:** if you are trying to build a `DEVELOPMENT` flavor of the Snow Leopard kernel, make sure `kxld` is configured to be built (in the various `conf` directories), otherwise the kernelcache will fail to link at boot. You'll also want `CONFIG_FSE`. You might find it easier to just change the compiler flags of the `RELEASE` variant than trying to get `DEVELOPMENT` to build and install.

# The Mock Kernel Patches

`patch_xnu-1456.1.26.diff` contains the patches we created to build `mach_kernel.sigpwny`.

It adds two new major components- `softpac` and `sotag`.

## SoftPAC

Pointer Authentication (aka `PAC`) is an ARM v8.3 ISA extension that allows for cryptographically signing pointers in memory.
Essentially, with PAC enabled, arbitrary read/ write no longer allows attackers to violate CFI as changing function pointers is difficult without a PAC bypass.

Usually, PAC requires special hardware extensions to function.
We have implemented a software version of PAC in `bsd/kern/softpac.c`.

The two major PAC instruction flavors (`pac*` and `aut*` for signing and verifying pointers, respectively) are replicated with the C functions `softpac_sign` and `softpac_auth`.
A SoftPAC signature takes three arguments- the "flavor" of the pointer (`SOFTPAC_DATA` or `SOFTPAC_INST`), the "key" (however, for this challenge, we don't use a key, in practice this is more analagous to the `salt` as used on ARM), and the pointer value itself.

Let's break down the three arguments and the rationale for including them.

Every pointer is either a data or instruction pointer. We denote this distinction as the pointer's "flavor". It is important to make a distinction between data and instructions so that references to data memory can never be swapped for instruction references (eg. function pointers).
This means that the same address should have a different signature depending on if the reference is intended to point to data or instructions.
We implement this by remembering what each pointer represents, and passing that information along to SoftPAC as the flavor.

Instead of using a key, we salt each signature with the location of the pointer itself in memory (which is how ARM Pointer Authenticated programs salt pointers in practice).
This has several beneficial properties from a defense perspective.
First, it means that two pointers that both point to the same location will have *different* signatures!
Second, it means that even if forgery is possible, the forged pointer can never be moved from its original address.
Third (which is the point most relevant to Mock Kernel), if an attacker has a mechanism for forging pointers, they cannot do so until they learn the location of the pointer itself!
Since SoftPAC protected pointers are stored on the kernel heap, this means that a kernel heap address leak is required for the specific object being forged.

Lastly, of course the pointer being signed needs to know what it points at, so we pass along the pointer value too.

<!-- In all consumers of the SoftPAC API in this challenge, the following convention is taken. -->

The following formula is used for calculating signatures (see `compute_pac`):

```
def calculate_pac(flavor, key, plainptr):
    digest <- md5sum(flavor, key, plainptr)
    pac <- xor_every_two_bytes(digest)
    return pac
```

We take the MD5 hash of the flavor + key + plainptr, and then XOR every two byte sequence of the hash together to produce a unique 16 bit number, representing the pointer's pointer authentication code (PAC).

When checking a pointer, we recompute the PAC (by first stripping the PAC bits from the pointer and sign extending to a canonical 64 bit virtual address to support both kernel and user mode VAs) and then check if the pointer's PAC matches the recomputed hash.
If they do not match, we immediately panic the kernel (unlike ARM 8.3 PAC, which only panics on use of an invalid pointer).

SoftPAC makes use of 16 bit PACs stored in bits 47 to 62 inclusive of a pointer.
Thus, a VA is represented by SoftPAC as follows:

```
  63   59   55   51   47   43   39   35   31   27   23   19   15   11    7    3  0
   |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |  |
   APPP_PPPP_PPPP_PPPP_PVVV_VVVV_VVVV_VVVV_VVVV_VVVV_VVVV_VVVV_VVVV_VVVV_VVVV_VVVV

V = Virtual Address bit
P = PAC bit
A = Canonical Address Space bit (0 = user, 1 = kernel)
```

To extract a PAC (bits 62 -> 47 inclusive), the bitmask `0x7FFF800000000000` followed by a right shift of `47` can be used.

Note that this is very similar to the 16-bit PAC behavior on ARM systems.

## Socket Tags

In `bsd/kern/sotag.c` we have added a new feature to BSD sockets called "Socket Tags" (or `sotag` for short).
A socket tag allows the user to add a `0x40` byte "tag" to a given socket file descriptor containing user specified data.
The intention here is that users can tag socket fds with extra metadata for use by the program.

Socket tags are controlled via `setsockopt` and `getsockopt` with the `SO_SOTAG_MODE` option.
Users should create a `sotag_control` struct and pass their desired command and arugments via this struct.

There are four commands, three of which are controlled by `setsockopt`:

- `CTF_CREATE_TAG`: Create a socket tag for a given socket.
- `CTF_EDIT_TAG`: Edit the socket tag of a given socket.
- `CTF_REMOVE_TAG`: Delete the socket tag of a given socket.

And one controlled by `getsockopt`:

- `CTF_SHOW_TAG`: Read the value of the socket tag.

Internally, socket tags are represented by `struct sotag`:

```c
struct sotag {
	char tag[SOTAG_SIZE];
	struct sotag_vtable *vtable;
};
```

The `tag` buffer is the user-controllable data, and the `vtable` pointer points to a `sotag_vtable`, which is a struct containing a single function pointer to a "dispatch" method that is used by `CTF_SHOW_TAG`.

The socket tag vtable is protected by SoftPAC, just like how a real C++ object's vtable would be protected by ARM Pointer Authentication.
The `sotag_vtable` pointer is a data pointer (`SOFTPAC_DATA`).
Inside of the vtable is a function pointer (`SOFTPAC_INST`) that by default points to `sotag_default_dispatch`.
The socket tag's vtable pointer, and the vtable entry **must** be correctly signed to use `CTF_SHOW_TAG` without causing a panic.

There are multiple vulnerabilities in the Socket Tag implementation, such as:
- A Use after Free if a tag is deleted and then read from/ written to.
- A double free if a tag is freed twice.
- Memory is leaked as the socket tag vtable is never freed if a socket tag is freed.
- Null pointer dereferences / uninitialized memory uses are possible if socket tags are edited/ viewed before being allocated.

## Non-Goals

This brief aside will document the author's intentions in implementing PAC here.
First, it should be obvious this PAC implementation is not cryptographically secure- this is intentional.
The reason for adding PAC to this challenge is to induce a dependence on a heap address leak on performing the exploit.
As there is no kASLR, it would be too easy otherwise!

The intention is that the PAC algorithm is reverse engineered and implemented in userspace.
Then, using the heap data and address leaks found by the exploit, all PACs are forged in userspace by the exploit code.

Another non-goal is forcing one specific path of exploitation.
You'll note that there are multiple vulnerabilities in the Socket Tag implementation that are not used by the intended exploitation path.
Keeping these bugs in just makes for a more interesting challenge :).

# Solving the Challenge

You're going to want a copy of the [`xnu-1456.1.26` source](https://github.com/apple-oss-distributions/xnu/tree/xnu-1456.1.26) with the patches applied open while working on this.

We are an unprivileged user and would like to elevate our privileges to root via gaining arbitrary kernel code execution.

First, let's take a look at what mitigations are present on Snow Leopard:
- SMAP/ SMEP are disabled
- kASLR is disabled
- Heap randomization and `kalloc_type` are not present on Snow Leopard

A binary exploitation author's dream!

## Working with Sotags
Let's start from the beginning- how do we interact with socket tags?

Take a look at `bsd/kern/uipc_socket.c:3233` (the `SO_SOTAG_MODE` option of `sosetopt`).
This is where three of the four sotag options are implemented- we can create a socket tag, edit a socket tag, and delete a socket tag.

Let's begin by creating a socket and attaching a sotag to it:

```c
// Create a socket
int fd=socket(AF_INET, SOCK_STREAM, 0);

// Setup a setsockopt control structure with our command (CTF_CREATE_TAG)
struct sotag_control opts;
opts.cmd = CTF_CREATE_TAG;
bzero(&opts.payload, sizeof(opts.payload));

// Create a sotag on this socket
setsockopt(fd, SOL_SOCKET, SO_SOTAG_MODE, &opts, sizeof(opts));
```

We can now edit the contents of the tag with the following:

```c
// Set the sotag user-controlled string to "AAAA..."
opts.cmd = CTF_EDIT_TAG;
memset(&opts.payload, 'A', sizeof(opts.payload));
setsockopt(fd, SOL_SOCKET, SO_SOTAG_MODE, &opts, sizeof(opts));
```

If you have a kernel debugger setup (eg. with `Qemu`'s gdb stub), you can pause the kernel and you should see your socket tag has been filled with user controlled bytes.

Lastly, we can free the socket tag with:

```c
// Free the sotag
opts.cmd = CTF_REMOVE_TAG;
setsockopt(fd, SOL_SOCKET, SO_SOTAG_MODE, &opts, sizeof(opts));
```

## Sotag Internals

Well, how does the kernel allocate and keep track of socket tags?
Let's look at what happens when we allocate a sotag.
In `uipc_socket.c:3243` (comments and debug strings omitted for brevity):

```c
case CTF_CREATE_TAG: {
  new_sotag = alloc_sotag(); // <- Defined in `bsd/kern/sotag.c`
  if (!new_sotag) goto bad;
  so->attached_sotag = new_sotag;
  break;
}
```

So, we do three things: 1) request a new sotag from the magic `alloc_sotag` method, 2) if it's `NULL` we return a failure code, and 3) assign the socket's `attached_sotag` pointer to point to the newly allocated socket tag. What happens in `alloc_sotag`?
In `bsd/kern/sotag.c:13`:

```c
struct sotag *alloc_sotag() {
  struct sotag *new_tag;
  new_tag = kalloc(sizeof(*new_tag));

  if (0 == new_tag) return ((struct sotag *)0);
  new_tag->vtable = (struct sotag_vtable *)kalloc(SOTAG_VTABLE_ALLOC_SIZE);

  if (0 == new_tag->vtable) {
      kfree(new_tag, sizeof(*new_tag));
      return ((struct sotag *)0);
  }

  new_tag->vtable->dispatch = sotag_default_dispatch;
  sign_sotag(new_tag);

  return new_tag;
}
```

To create a sotag, the kernel allocates some memory from the general purpose `kalloc` allocator. (This will be important later!).
Then, we allocate some memory for the `vtable` field of the sotag.
Something that is important to note is that `SOTAG_VTABLE_ALLOC_SIZE` is `0x100` bytes, which means that the `vtable` allocated will always be `0x100` byte aligned. This will also be important later!

Next, we do some NULL checks, and finally set the `vtable` to point to `sotag_default_dispatch` and encrypt the sotag with SoftPAC.

Well what's all this nonsense about a vtable?
The vtable is used by the sotag method we haven't covered yet, `CTF_SHOW_TAG` (footnote: since this is the only option readable with `getsockopt`, the kernel doesn't actually check that `CTF_SHOW_TAG` was passed in).

In `uipc_socket.c:3571`, `sogetopt` defines what happens when you use `getsockopt` on a sotag (aka the `CTF_SHOW_TAG` command):

```c
case SO_SOTAG_MODE: {
  /* Read out the tag value from this socket. (default behavior of sotag_call_dispatch). */
  /* If the dispatch method is overriden, this will do whatever the new behavior dictates. */
  struct sotag_control sotag_options;
  sotag_call_dispatch(so->attached_sotag, &sotag_options.payload.tag, so->attached_sotag->tag);
  error = sooptcopyout(sopt, &sotag_options, sizeof(sotag_options));
  break;
}
```

When reading from a sotag, the kernel utilizes `sotag_call_dispatch` (in `bsd/kern/sotag.c`) to first ensure the sotag and vtable are correctly signed, then jumps to the `dispatch` method saved in the sotag vtable.
This defaults to `sotag_default_dispatch`, which implements the desired `memcpy` behavior to copy the socket tag's payload into the `sotag_control` that is later `copyout`'ed into userspace.
Hmmm... I wonder if there's a way to change the vtable to point to some other method...

Now that we've seen how the kernel creates and uses sotags, what happens when we delete one?
Looking at `uipc_socket.c:3267`, let's see what happens when we free a sotag:

```c
case CTF_REMOVE_TAG: {
  ...
  kfree(so->attached_sotag, sizeof(*new_sotag));
  break;
}
```

Aha! This smells like a vulnerability- we never clear `so->attached_sotag`!
This is a classic Use-after-Free situation.
Let's look ahead to think about how we can exploit this behavior to gain elevated privileges.

## Mach IPC
The key observation here is that once the sotag is deleted, the memory can be reclaimed by something else.
And since we have a dangling reference to the sotag via the socket structure (`attached_sotag`), as long as the socket is still around we can interact with that memory as if it were a sotag.
That is, we can use `CTF_EDIT_TAG` and `CTF_SHOW_TAG` to arbitrarily edit and potentially leak the contents of the memory the sotag used to occupy!

So, let's start by replacing the space that the sotag used to occupy with something interesting.

The XNU kernel is built on top of the Mach microkernel which provides Mach messages.
Mach messages are used for inter-process communication (or IPC).
We're going to use them as an easy way to get the kernel to allocate conveniently sized attacker controlled data for us.

A Mach OOL (out of line) message is a special kind of Mach message that is particularly useful here.
Why?
Well, because it ends up in a very convenient `kalloc` where *we* control the size.
This is important because we can pick a size that matches the size of a sotag, making it likely that our Mach OOL message will be allocated where the freed sotag was.
We can send a bunch of Mach OOL messages, and eventually one of them will replace the old sotag (since they're the same size, and both allocated with the general purpose `kalloc` allocator!)

Let's see the kernel code responsible here to get a better idea of what this means.

When you call `mach_msg`, your syscall will travel through the Mach trap table (`osfmk/kern/syscall_sw.c`) and land in the `mach_msg_trap` function (in `osfmk/ipc/mach_msg.c:566`).
(Interesting footnote: mach traps are also called through the syscall interface, just with negative syscall numbers- see `osfmk/i386/bsd_i386.c:655`).

`mach_msg_trap` is just a wrapper around `mach_msg_overwrite_trap` (a more general purpose version of `mach_msg_trap`) which calls `ipc_kmsg_copyin` to copy your Mach message into the kernel.
Note that in the kernel, Mach messages are called `ipc_kmsg_t`'s.

For "complex" Mach messages (those with out of line descriptors, like ours), `ipc_kmsg_copyin` calls `ipc_kmsg_copyin_body`, which calls `ipc_kmsg_copyin_ool_descriptor` to copy the OOL descriptor in.
For small descriptors, `vm_map_copyin_kernel_buffer` (`osfmk/vm/vm_map.c:6670`) eventually is used to allocate a new `vm_map_copy` where our attacker controlled data is appended to the end.
The size of this allocation is `kalloc_size = (vm_size_t) (sizeof(struct vm_map_copy) + len)`, where the attacker controlls `len` via the OOL descriptor length.

**If we create a bunch of OOL messages with the same(ish) length of a sotag, we will end up with a `vm_map_copy` overlapping with the sotag!**

Now that we can overlap the `sotag` with a sprayed heap object, what's next?

Recall a Sotag is structured as follows (`bsd/sys/sotag.h`):

```c
#define SOTAG_SIZE ((0x40))
struct sotag {
	char tag[SOTAG_SIZE];
	struct sotag_vtable *vtable; /* +0x40: First controlled bytes by OOL mach message type confusion */
};
```

The sotag has `0x40` bytes of attacker-controllable data followed by `8` bytes for the vtable pointer.
Interestingly enough, the size of the attacker controlled data (`sotag.tag`) matches exactly that of the `vm_map_copy` we are eventually going to create a type confusion with.

By allocating lots of OOL messages, we will call `vm_map_copyin_kernel_buffer` many times, each time performing a `kalloc` of `0x40` plus however long our spray content is.
Then, we will copy the spray content (the contents of the OOL message described by the descriptor) to this new allocation starting at `+0x40` from the beginning of the allocation- perfectly overlapping the vtable field.

Note that until now, there was no way for the attacker to change the `sotag.vtable` field.
However, a sprayed OOL mach message will let the attacker do just that!
But they need to know the value to put in the `vtable` field before the spray begins...


So, let's look in detail at what happens when a `vm_map_copy` is allocated on top of a `sotag`. `vm_map_copy` is defined in `osfmk/vm/vm_map.h` (and note that a `vm_map_copy_t` is `typedef`'d to be a pointer to this struct):

```c
struct vm_map_copy {
	int			type;
#define VM_MAP_COPY_ENTRY_LIST		1
#define VM_MAP_COPY_OBJECT		2
#define VM_MAP_COPY_KERNEL_BUFFER	3
	vm_object_offset_t	offset;
	vm_map_size_t		size;
	union {
	    struct vm_map_header	hdr;	/* ENTRY_LIST */
	    vm_object_t			object; /* OBJECT */
	    struct {
		void			*kdata;	      /* KERNEL_BUFFER */
		vm_size_t		kalloc_size;  /* size of this copy_t */
	    } c_k;
	} c_u;
};
```

Upon triggering a successful Use-after-Free, all of these fields are writeable through `CTF_EDIT_TAG`.
If we want to read them, we need to ensure the vtable pointer is left exactly in tact, as if it changes, we cannot use `CTF_SHOW_TAG` through `getsockopt` (recall that `getsockopt` uses the vtable, so it needs to be uncorrupted to read anything from the sotag).

## Getting a Heap Leak

Recall that the vtable pointer is `0x100` byte aligned- this means that the least significant byte of the vtable field will always be zero.
So, we should make sure to keep the vtable exactly as-is until we are ready to change it.
We can perform a Mach OOL spray with descriptor length 1 byte (specifically the byte `0x00`) to overwrite just the least significant byte of the vtable field while keeping all other bytes unchanged (we cannot perform a zero length OOL spray due to `osfmk/ipc/ipc_kmsg.c:2037`).
Shout-out little endian systems!

If we do this and successfully overlap a `vm_map_copy` with a `sotag`, we can read and write all fields of the `vm_map_copy`!

The `kdata` field (at offset `+24` from the start of the tag) is of particular interest, as it points right to the end of the `vm_map_copy` (aka where the `vtable` is held in memory).

So, the steps to leak the address of the `sotag.vtable` field are as follows:

1. Allocate a sotag.
2. Free it.
3. Allocate a bunch of Mach OOL messages with descriptor length 1 to overlap the freed sotag.
4. Use `getsockopt` (with the in-tact vtable) to leak the current "sotag" (really a `vm_map_copy`) contents, and read the `kdata` field.

At this point, we can reliably leak the address of the `sotag.vtable` (and therefore know where the `sotag` is in memory).
We will need this address in order to defeat PAC.

## Sotag + SoftPAC

So far we have neglected to describe what `sign_sotag` actually does and what it means for a sotag to be "signed".

Let's take a look at `sign_sotag` in `bsd/kern/sotag.c:36`:

```c
void sign_sotag(struct sotag *t) {
  if (!t) return;
  t->vtable->dispatch = softpac_sign(
      SOFTPAC_INST,
      &(t->vtable->dispatch),
      t->vtable->dispatch
  );

  t->vtable = softpac_sign(
      SOFTPAC_DATA,
      &(t->vtable),
      t->vtable
  );
}
```

A signed sotag has two PAC-protected pointers.
First, we encrypt the contents of the vtable (which again, is just 1 function, even though we allocate `0x100` bytes for it).
This one function is the `dispatch` method.
We sign `dispatch` as an instruction pointer, since it directly points to code to run.
We salt it by passing the *address* of the `dispatch` pointer *itself* for this specific vtable.

Then, the `vtable` pointer itself (pointing to the vtable which is allocated with `kalloc(0x100)`) is encrypted as a signed data pointer.
This might seem counter-intuitive as vtables are used for function dispatches, why are we signing it as a data pointer and not an instruction pointer?
Well, `sotag.vtable` doesn't point to a function to *run*, but a table of function *pointers* (specifically, this table only has one valid element).
So, we sign it as a data pointer.

Much like the vtable entry case, we salt the vtable pointer with a value that will be unique for each sotag (its address!).
We pass the *address* of the `sotag.vtable` for *this specific sotag* into SoftPAC as the key.
This means that two different sotags will have *different* signatures for their `vtable` field, even if they pointed to the same vtable somehow.
**If an attacker wants to forge the PAC for the `vtable` pointer, they will need to know where this sotag is allocated on the kernel heap!**

You'll find that this is the same behavior in ARM 8.3 PAC protected C++ binaries for C++ objects (except ARM systems obviously use a real hardware key and actually cryptographically secure algorithms, at least I hope).

## Defeating SoftPAC

So, to recap.

We have found a use after free vulnerability in the socket tagging feature, and used it to create a type confusion where the kernel has allocated a `vm_map_copy` on top of a `sotag` that is still being used, despite having been freed.
We have then used this capability to leak `vm_map_copy.kdata`, which points exactly to `sotag.vtable` for the sotag.
We can do this by reading from the sotag via `getsockopt`, which leaks `vm_map_copy.kdata` for whichever OOL message got allocated over the `sotag`.

Now, we know where in the heap our `sotag` is stored, and would like to forge the PAC for its vtable to redirect `vtable` and then `vtable->dispatch` to point to some attacker controlled code.

Luckily for us, this version of PAC doesn't use any secret keys, and is in fact just basically the MD5 hash of a few things we already have learned through leaks.

Let's look at the SoftPAC internals.
In `bsd/kern/softpac.c:4`:

```c
pac_t compute_pac(softpac_flavor_t flavor, softpac_key_t key, u_int64_t plainptr) {
  MD5_CTX ctx;
  u_int8_t digest[MD5_DIGEST_LENGTH];
  pac_t pac = 0;
  int i;

  MD5Init(&ctx);

  MD5Update(&ctx, &flavor, sizeof(flavor));
  MD5Update(&ctx, &key, sizeof(key));
  MD5Update(&ctx, &plainptr, sizeof(plainptr));

  MD5Final(digest, &ctx);

  for (i = 0; i < MD5_DIGEST_LENGTH / 2; i++) {
      pac ^= digest[2*i] | (digest[2*i+1] << 8);
  }

  return pac;
}
```

We just compute the MD5 hash of `(flavor, key, pointer's value)` and then XOR the bytes of the MD5 together to create a 16 bit PAC.
In fact, while this snippet is of kernel code, this code can be basically used as-is in userspace with the OpenSSL crypto library.

With the `vm_map_copy.kdata` leak, we have all the pieces we need to forge the entire `sotag->vtable->dispatch` PAC chain for the UaF'd `sotag`.
We have to forge two pointers: `sotag->vtable` should be redirected to point to some forged vtable, and then `forged_vtable->dispatch` needs to be forged to point to attacker controlled code.
For now, let's not worry about where the attacker controlled code is, and focus on forging the signatures.

We can put our forged vtable anywhere within the `sotag.tag` area, which again, we have total write control over.
In my exploit, I put it at `&sotag.vtable - 56` (just some 8 byte area that lives in `sotag.tag`. I chose `-56` as this puts us 8 bytes after the beginning of the sotag- the first 8 bytes are interesting as the freelist will write pointers there, so I didn't want to overwrite that).


First, we can forge the `vtable` to point to `&sotag.vtable - 56` by recalculating the PAC just like `sign_sotag` does.
The flavor is `SOFTPAC_DATA`, the key/ salt is the address of the vtable itself (again, which we leaked earlier from `vm_map_copy.kdata`), and the pointer destination is where the new vtable goes- `&sotag.vtable - 56`.

Next, we need to populate this fake vtable with a signed instruction pointer that matches the one the code expects to find within the vtable.
We can sign this with flavor `SOFTPAC_INST`, key/ salt of `&sotag.vtable - 56` (the address of the forged `dispatch` field where we will write this signed pointer), and the destination can be wherever we like!

We can easily write the forged `dispatch` pointer into `&sotag.vtable - 56` by just using `setsockopt` to fill in the `sotag.tag` field like before.
However, changing the vtable is hard, as there is currently an OOL mach message of length 1 that lives there.

We can "undo" the first spray by using `mach_msg` with `MACH_RCV_MSG` to free all OOL messages, freeing the one that was allocated over our `sotag`.
Next, we can just repeat the spray, except this time with 8 byte descriptors instead of 1 byte ones, and fill in the entire `vtable` field in the freed `sotag` with the forged signed new vtable (that points back to the `sotag`, where our fake `dispatch` field is waiting).

After the second round of heap spray, everything is in place.
Now, what attacker controlled code to actually put there?

## Final Payload
Normally, if SMAP/ SMEP were enabled, this is the part where we would write a kernel ROP/ JOP payload, probably making use of various leaked pointers to bypass kASLR too.
But luckily for us, Snow Leopard doesn't support any of that.

So, we can literally just jump to userspace addresses, and the kernel will run code from userspace as if it were part of the kernel!

We'd like to elevate our privileges, which just means setting a few fields in our `ucred` belonging to this BSD process.
We can get the BSD process by calling `current_proc()`, and then get the `ucred` struct from that with `proc_ucred()`.
Note that you don't actually need to perform any function calls if you can read your task struct from the CPU's `gs` segment, but that's actually more work in this case since there's no kASLR anyways.

So, our payload looks like the following:

```c
// Hard-coded addresses extracted from kernel binary:
#define CURRENT_PROC 0xffffff800025350cULL
#define PROC_UCRED 0xffffff8000249967ULL

// This is the function we want to get the kernel to call
// It will elevate our privileges to root mode
void target_fn() {
  void *p = ((void *(*)())CURRENT_PROC)();
  struct ucred *c = ((ucred *(*)(void *))PROC_UCRED)(p);
  c->cr_uid = 0;
  c->cr_ruid = 0;
  c->cr_svuid = 0;
  c->cr_rgid = 0;
  c->cr_svgid = 0;
  c->cr_gmuid = 0;
}
```

And that's all there is to it!
If we set the forged `dispatch` to point to `target_fn` in userspace, whenever the kernel next tries to use the sotag dispatch, it will call `target_fn` which then grabs our task and elevates our privileges.

So, to trigger the final exploit, all we need to do is one last `getsockopt` against the `sotag` which will use `sotag_call_dispatch` to dereference our correctly forged `vtable->dispatch` and jump to our code.

And with some luck from the heap spray, we should suddenly have become root!

# Recap: An Overview

The entire exploit consists of the following steps:

1. Create a socket.
1. Attach a sotag to it.
1. Free that sotag (but the socket still maintains a reference to it!)
1. First round heap spray: Spray 1 byte long Mach OOL messages to overlap with the sotag. 1 byte so that our spray data doesn't overwrite `sotag.vtable`, an important value that should not be changed (yet). A `vm_map_copy` will be allocated on top of the `sotag`.
1. Learn where our sotag is allocated (specifically, the address of `sotag+0x40`, AKA the `vtable` field) by reading 8 bytes from offset `+24` in the sotag. This is `vm_map_copy.kdata`.
1. Undo the first spray by receiving all messages, the `vm_map_copy` that was allocated over our `sotag` is freed.
1. Using the leaked `kdata`, forge a fake `vtable.dispatch` inside of `sotag.tag`, the attacker controlled bytes in the socket tag, and forge a pointer to it for `sotag.vtable`.
1. Fill in the fake vtable `dispatch` field with `setsockopt`.
1. Second round heap spray: Spray 8 byte long Mach OOL messages to overwrite the sotag vtable field to point to the forged vtable.
1. Trigger the forged vtable using `getsockopt`, this will run the attacker payload living in userspace to escalate our privileges.
1. `cat /flag`.

## A JOP-Based Solution

Thanks to [2much4u](https://twitter.com/2much4ux) for contributing a solution that does not involve the `ret2usr` technique shown above, instead using kernel JOP gadgets as the payload.

To see 2much4u's exploit, checkout the `solve_2much4u` directory.

Thanks 2much4u!

# Closing Thoughts

I hope you had fun with this challenge!
I definitely had a lot of fun messing with the Snow Leopard kernel.

If you found a cool way to exploit this challenge not covered here, reach out: https://twitter.com/0xjprx.

### Practical Debugging Advice

Here's a few things I found that made debugging my exploit easier.

- Use single user mode with `serial=3`! This gives you a serial shell, a really fast booting kernel, and a super noise-free environment with a relatively deterministic heap.
- Use Qemu's GDB stub for debugging the kernel! Bonus points for using the XNU Python tools.
- Go step by step by making your exploit wait for user input before proceeding between steps. This gives you time to pause the kernel and inspect the heap state before continuing to ensure that your exploit is doing what you expect.


### Further Reading
While the very basics of Mach IPC were touched on here, there is much more to read about this topic.
Here's a list of some reading materials that may be useful in case you want to learn more about xnu!

https://googleprojectzero.blogspot.com/2020/06/a-survey-of-recent-ios-kernel-exploits.html

https://googleprojectzero.blogspot.com/2019/12/sockpuppet-walkthrough-of-kernel.html

https://github.com/kpwn/tpwn
