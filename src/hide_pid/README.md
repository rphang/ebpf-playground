# hider

![hider_demo](../../resources/hide_pid_demo.gif)

All processes in Linux have a PID (Process IDentifier) that is used to identify them. This is a unique number that is assigned to each process by the kernel. Programs like `ps` and `top` use this PID to identify processes. They work by listing the contents of the `/proc` directory, which contains a directory for each process, named after the PID of the process.

So hiding a process is as simple as removing the directory for that process from `/proc`, right? The problem is that the kernel doesn't allow you to remove directories from `/proc`. So how do we hide a process?

## Tracepoints

When you're using `ps` or `top`, the `getdents64` syscall is used to list the contents of the `/proc` directory. This syscall is traced by the kernel, and a tracepoint is generated for each invocation of this syscall. We can use this tracepoint to alter the contents of the `/proc` directory at execution time. (So we are not really deleting the directory, we are just making it disappear at the output of the syscall)

## Usage

After compiling the program, run it as root:

```bash
$ ./hider PID|FILE_NAME|DIR_NAME
```

or

```bash
$ ./hider
```

Yup .. that's it... The program will hide itself from the output of `ps` and `top`.
To unhide everything, simply kill the program.

This current implementation support:

- [x] Hiding multiple processes at once
- [x] Hiding directories / files
- [x] Dynamically adding / removing elements to hide at runtime

## Detection - finder.c

I provided a simple program that can be used to detect the presence of hidden elements in any directory. Here is an example of how to use it:

First, compile the program:

```bash
$ make finder
```

Then (when ran with the `hider` program running):

```bash
$ ./finder /proc
getdents:
getdents64:
- Anomaly between 10960 (848071) and 64 (848159)

Sanity check failed:
- Anomaly between getdents and getdents64 (we might be able to disclose more files)


Total anomalies: 1
(/proc) is hidding some stuff !
```

The implementation of `hider` is fairly easy to detect. As we are only affecting the output of the `getdents64` syscall, we can use `getdents` to find the hidden files / directories. If we were to also hide the `getdents` syscall, we would have to use a different approach by checking the `dirent64` structure returned by the `getdents(64)` syscall for anomalies (which is also implemented in `finder.c`).

>[!NOTE]
> We can apply the same technique with symlink if malware/rootkit are filtering over the `/proc` or any other directories as they cannot resolve the symlink.

## Supported Kernels

This program should work from kernel 4.7.0 and above (with eBPF support enabled). It was tested on kernel 5.4.0.

## Credits

Most of the code is based on [bad-bpf](https://github.com/pathtofile/bad-bpf) but it's implementation lacked some features such as hiding multiple processes at once and specifying paths to hide.

> **Note:** This is a PoC and it still have flaws. For example, if you hide a folder, the return value of the `getdents64` syscall will be different from the number of bytes read.