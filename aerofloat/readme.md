AeroCTF 2020 - aerofloat
---------------
pwn

desc 
---------------

- ROP
- RTL Chaining 
- Return to CSU
- Fake Stack

files 
---------------

- challenge 
- libc.so.6(glibc 2.29->ubuntu 19.04)=> 커스텀 라이브러리로 추정 
- ld-linux-x86-64.so.2

checksec 
---------------
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
solution 
---------------
시작하면 이름을 입력받고 티켓별 id와 점수를 입력받아 저장한다.
이름 입력시는 128바이트 입력제한이 걸려있고, 이름 인덱스는 전역변수영역에있다.
id 입력시는 8바이트 입력제한, 점수 입력시는 lf로 입력받는다.
그후 리스트를 출력하는 기능이 있고 최대 입력가능 갯수제한은 없어보인다.

```
    printf("{?} Enter your ticket id: ");
    read_buf(&v4[16 * v7], 8);
    printf("{?} Enter your rating: ", 8LL);
    __isoc99_scanf("%lf", &v4[16 * v7 + 8]);
    printf("{+} You set rating <%lf> to ticket <%s>\n", &v4[16 * v7], *(double *)&v4[16 * v7 + 8]);

```
입력받은값을 저장하는 배열은 스택영역 rbp-C0 에 위치하는데
배열에 접근할때 v4[16*idx],v4[16*idx+8] 식으로 접근하므로, 일정 갯수를 넘기면
입력위치와 출력위치를 조절할 수 있어보인다. 12개만 움직여도 출력위치 바꿀 수 있을듯. 

```
  char v4[172]; // [rsp+0h] [rbp-C0h]
  int v5; // [rsp+ACh] [rbp-14h]
  unsigned int i; // [rsp+B0h] [rbp-10h]
  unsigned int v7; // [rsp+B4h] [rbp-Ch]
  int v8; // [rsp+B8h] [rbp-8h]
  int v9; // [rsp+BCh] [rbp-4h]
```
다만 이때 주의해야 하는게, 다른 지역변수들이 영향을 받을 수도 있다. 
v5변수는 메뉴 입력시 사용하는 변수니까 크게 주의할 필요 없음
i는 반복문 진입시 초기화되니까 주의할 필요 없음
v7은 레이팅 인덱스를 조절하는 변수. 사실 이 변수만 바꾸면 더이상 입력값을 넣을 필요는 없음
v7이 C위치에 있으니까 11번 입력한 이후에 접근이 가능함. 

12번째 입력에서 id의 다섯번째 글자+1 값이 레이팅 갯수가 됨. ret위치에 접근하는게 목적인데
여기서 libc leak과 원샷가젯을 이용한 오버라이트를 순차적으로 시도해봐야한다. 
스택에 있는 값에 손상을 주지않고 그대로 출력해보고 싶은데, 문자열을 입력하면 끝자리를 00으로 바꾸기 때문에 손상이 날수밖에 없다. 
그렇다면, leak을 한번에 할 생각을 하지말고 리턴루틴을 만들어 놓은 다음 leak-overwrite를 하는 순으로 해보자.

프로그램 내용대로면 v9가 1이 아닐때 while문이 동작한다. 스택을 덮어쓰면서 v9의 위치인 rbp-8에 1이 들어가면 메인함수가 리턴된다. 

```
def dh(s):
    return struct.unpack('!d',("0"*10+hex(s)[2:]).decode('hex'))[0]
```

이때 발생하는 문제점. lf 형식으로 입력을 받기때문에 실제 메모리에 저장되는 값이 다르게 나온다. 
이를 유의하여 ret위치에 메인함수의 시작 주소를 덮어쓸수 있다.  

음, 복잡하게 할것 없이 그냥 rop를 할수도 있긴하겠다. ret위치부터 아래를 쭉 덮어쓸 수 있기 때문.
int 0x80 가젯이 없으므로 libc 릭이 필요한 상황. 
정리하면, 첫 입력에서 libc를 릭한 다음 , rbp가 망가지기 때문에 전역변수 영역으로 스택을 피보팅해주고,
두번째 입력부터는 릭한 주소를 가지고 원샷가젯을 호출하는 명령을 전역변수 영역에 구성해준다. 
그 다음 마지막 리턴때 전역변수 영역으로 돌아가면 될듯. 

프로그램이 시작할때 전역변수 영역에 입력을 받는데, 여기에 미리 값을 세팅해놔야한다.
제일 앞 8바이트는 입력받을 전역변수의 주소값을,
그 다음 8바이트부터는 rop 체인을 미리 구성해놓자. 

rop를 구성해보면

0. 전역변수 영역에 read 함수를 실행할 수 있는 체인 구성 
- pop rdx 가젯이 없으므로 return to csu 를 구성해야함 . 
- csu 1
- rbx -> 0, rbp->0, r12->edi , r13->rsi, r14->rdx, r15->함수got주소
- 이때 입력값이 들어갈 위치는 csu의 pop을 고려하여 정해야함. 
- csu 2 
1. leak을 위해 puts의 got와 plt 배치
- pop rdi ; ret ;
- puts got 
- puts plt
2. 전역변수 영역으로 스택 피보팅 (미리 rbp 바꿔놓아야함.)
- leave ret 
3. read함수 실행되면 전역변수 영역에 명령어 구성  
- 원샷가젯의 주소값 입력 

이후 실행시 4를 입력해 반복문에서 탈출, main함수의 return 구문으로 진입하게 만들면 쉘이 떨어진다.







