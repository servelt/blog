---
title: ret2dlresolve
published: 2026-06-06
tags: [Pwnable]
category: Concept
---
# 개요
이번 글은 `Rubiyalab의 포너블 스터디 주제 중` Ret2dlresolve에 대해서 공부하면서 배운 것들을 정리한 글이다.<br>
재밋게 봐주길 바란다!

# Ret2dlresolve란?
기본적으로 Libc 함수를 실행할땐 plt, got를 사용하게 된다.
또한 got은 libc의 주소를 저장하는 역할을 하고,
plt는 got을 참조하여 libc 함수를 실행하는 역할을 하게 된다.

특히 plt, got의 경우 바이너리에 존재하는 Libc 함수에 대해서만
존재하게 되는데, ret2dlresolve의 경우는 바이너리에서 호출된적이 없지만,
로더를 활용해 원하는 Libc함수를 불러오는 기법이다.

# Lazy Binding
기본적으로 got을 덮어 실행 흐름을 조작하는 기법인
got Overwrite를 막기 위한 보안 기법이 켜져있으면 Full RERLO,
꺼져있으면 Partial RELRO라고 부르게 되는데, 
Full RELRO의 경우는, 파일이 실행됨과 동시에 got에 Libc주소가 써지지만,
대부분의 Partial RELRO는 plt를 실행함과 동시에 Libc주소를 채워넣는
Lazy Binding 방식을 자주 사용하게 된다.

Lazy Binding 방식은 아래와 같이 진행된다
```text
1. plt 호출
2. got 호출 (got가 채워져 있을시 여기서 끝) 
3. plt0 호출 (나중에 어느 got을 채울지 모르니 인덱스를 백업)
4. _dl_runtime_resolve 호출
.
.

```

## Main 함수 호출
일단 위에 내용을 직접 보며 분석하기 위해서
Partial Relro인 바이너리를 하나 컴파일 한 후
분석을 진행하게 되었다. 특히 그 내용은 아래와 같다.
```asm
endbr64
push   rbp
mov    rbp,rsp
mov    edi,0x402004
mov    eax,0x0
call   0x401040 <printf@plt>
mov    edi,0x402007
mov    eax,0x0
call   0x401040 <printf@plt>
mov    eax,0x0
pop    rbp
ret
```
간단히 printf함수를 총 두 번 호출 하는것을 알 수 있었다.

## printf@plt 호출
이제 main코드를 보면 모든 call에서 printf 함수 주소 자체 대신
printf@plt를 활용해 호출하는것을 알 수 있고, 
printf@plt를 디스어셈블 해보면 아래와 같았다.
```asm
endbr64
bnd jmp QWORD PTR [rip+0x2fcd]      # 0x404018 <printf@got[plt]>
nop    DWORD PTR [rax+rax*1+0x0]
```
확인해보니 printf@got으로 그대로 점프하는것을 알 수 있었다.

## printf@got 호출
이제 got을 호출하는것을 확인했으니 안에 내용을 뜯어보면 
특정 주소가 나오는걸 알 수 있었다.
```asm
0x404018 <printf@got[plt]>:     0x0000000000401030
```

이제 got 안에 주소를 찾았으니 디스어셈블을 해보면 
아래와 같은 어셈블리 코드가 나오는것을 확인 할 수 있었다.
```asm
endbr64
push   0x0
bnd jmp 0x401020
nop
```
확인해보면 특정값을 스택에 push한 후 특정 주소로 점프하는걸 알 수 있다.
여기서 push 한 값은 현재 내가 실행한 libc 함수의 번호를 뜻하게 되고,
점프하는 곳은 plt0이 된다.

## plt0 호출
이제 plt0가 호출되는걸 알았으니 그 주소를 디스어셈블 해보면 아래와 같다
```asm
push   QWORD PTR [rip+0x2fe2]        # 0x404008
bnd jmp QWORD PTR [rip+0x2fe3]        # 0x404010
nop    DWORD PTR [rax]

0x404010:       0x00007ffff7fd8d30
```
확인해보면 got에서 본 것과 매우 동일하게 특정 값을 push하고
특정 주소에서 값을 꺼내 점프하는것을 알 수 있다.
여기서 push하는 값은 linkmap 구조체로,
여러가지 구조체들의 시작주소를 가지고 있는 구조체이다
그리고 이후엔 특정한 주소로 점프하게 되는데
그 주소가 바로 _dl_runtime_resolve이다.

## _dl_runtime_resolve 호출
이후 _dl_runtime_resolve를 디스어셈블 해보면 아래와 같다
```asm
endbr64
push   rbx
mov    rbx,rsp
mov    QWORD PTR [rsp],rax
mov    QWORD PTR [rsp+0x8],rcx
mov    QWORD PTR [rsp+0x10],rdx
mov    QWORD PTR [rsp+0x18],rsi
mov    QWORD PTR [rsp+0x20],rdi
mov    QWORD PTR [rsp+0x28],r8
mov    QWORD PTR [rsp+0x30],r9
(생략)
mov    rsi,QWORD PTR [rbx+0x10]
mov    rdi,QWORD PTR [rbx+0x8]
call   0x7ffff7fd5e70 <_dl_fixup>
mov    r11,rax
(생략)
mov    r9,QWORD PTR [rsp+0x30]
mov    r8,QWORD PTR [rsp+0x28]
mov    rdi,QWORD PTR [rsp+0x20]
mov    rsi,QWORD PTR [rsp+0x18]
mov    rdx,QWORD PTR [rsp+0x10]
mov    rcx,QWORD PTR [rsp+0x8]
mov    rax,QWORD PTR [rsp]
mov    rsp,rbx
mov    rbx,QWORD PTR [rsp]
add    rsp,0x18
jmp    r11  
```
간단히 호출하기 위한 함수의 인자들을 백업한후,
plt쪽에서 스택에 삽입했던 인덱스와 linkmap 구조체를
그대로 _dl_fixup 함수로 넘겨서 처리하는걸 알 수 있었다.
그리고 _dl_fixup 함수가 끝난 이후엔 함수의 리턴값으로 그대로 점프하는걸 알 수 있었다.

## _dl_fixup
이제 마지막으로 _dl_fixup을 확인해보면 아래와 같다
```c
void _dl_fixup(struct link_map *l, unsigned long reloc_arg){
    // .dynsym 구조체 시작 주소
    const Elf64_Sym *dynsym = l->l_info[DT_dynsym]->d_ptr;

    // .dynstr 구조체 시작 주소
    const char *dynstr = l->l_info[DT_dynstr]->d_ptr;
    
    // .got.plt 구조체 시작 주소
    uintptr_t pltgot = l->l_info[DT_PLTGOT]->d_ptr;

    // .rela.plt 구조체 시작 주소
    const Elf64_Rela *rerlaplt = l->l_info[DT_JMPREL]->d_ptr;

    // 인덱스를 통해 relra 구조체 획득 (써넣을 got 주소 존재)
    const Elf64_Rela *needrerlaplt = rerlaplt + reloc_arg;

    // r_info 상위 4바이트만 추출하여 인덱스 획득후 dynsym 획득
    const Elf64_Sym *needdynsym = &dynsym[(needrerlaplt->r_info)/ 0x100000000];

    // 나중에 원래 심볼 정보를 넘기기 위해 저장
    const Elf64_Sym *tmpdynsym = needdynsym;

    // 가져온거 써넣을 got 주소
    void *rel_addr = l->l_addr + needrerlaplt->r_offset;

    // relra 구조체 relocation 검사
    assert(ELF64_R_TYPE(needrerlaplt->r_info) == R_X86_64_JUMP_SLOT);

    char *name = dynstr + needdynsym->st_name; // 찾으려는 함수 이름 위치 계산

    unsigned char visibility = dynsym->st_other & 0x03; // 외부함수 여부 2비트 추


    if (visibility == 0){ // 외부 함수이고, 공개 함수일때,
    
        // 인자로 받은 인덱스 토대로 찾으려는 함수의 이름을 가져와서 찾기,
        // 이후 찾았으면, 함수가 존재하는 바이너리의 link-map 구조체 반환  
        result = _dl_lookup_symbol_x(
            dynstr + sym->st_name,
            l,
            &sym,
            l->l_scope,
            version,
            ELF_RTYPE_CLASS_PLT,
            flags,
            NULL
        );
    }


    // 실제 함수 주소 계산
    value = DL_FIXUP_MAKE_VALUE(
        result,
        SYMBOL_ADDRESS(result, sym, false)
    );


    // got에 값쓰기
    return elf_machine_fixup_plt(
        l,
        result,
        refsym,
        needdynsym,
        needrerlaplt,
        rel_addr,
        value
    );
}

typedef struct {
    ElfW(Addr) l_addr; // 실제 elf의 주소
    char *l_name; // ELF의 이름 (예: libc.so.6, prob)
    ElfW(Dyn) *l_ld; // dynamic 섹션 주소
    struct link_map *l_next; // linkmap 이중 연결리스트 fd
    struct link_map *l_prev; // linkmap 이중 연결리스트 bk
    struct *l_info[6]; // 섹션 구조체에 대한 각 dynamic 구조체의 주소
} link_map;

typedef struct {
    Elf64_Sxword d_tag; // 섹션 구조체에 따른 태그

    union { // 태그에 따라 달라짐
        Elf64_Xword d_val; // 구조체 크기
        Elf64_Addr  d_ptr; // 구조체 주소
    } d_un;
} dynamic;

typedef struct {
    int64_t r_offset; // 써넣을 got 오프셋
    uint32_t sym_index; // .dynsym 인덱스 (r_info 상위)
    uint32_t relocation; // sym_index 계산 방식 (대부분 7)
    int64_t r_addend; // 사실상 패딩
} rela;

typedef struct
{
    long long st_name; // .dynstr의 오프셋
    unsigned char st_info; // 심볼의 데이터 타입(대부분 12)
    unsigned char st_other; // 숨김처리된 함수 여부(대부분 0)
    long long st_shndx; // 섹션 넘버
    struct *st_value; // 함수의 libc 내부 오프셋  
    int st_size; // 함수 길이
} dynsym;

//linkmap : 여러 ELF관련 정보와 다른 구조체들 주소를 저장하는 l_info
// relra.plt : 주소를 써넣을 got 주소, dynsym+relocation 값
// .dynsym : .dynstr 구조체에서 내가 가져올 함수 이름이 존재하는 오프셋 저장
// .dynstr : 가져올 libc 함수의 이름이 저장됨
```
해석해보면, 인자로 받은 linkmap의 l_info요소를 통해 
필요한 구조체를 가져온후, 인자로받은 인덱스를 통해 
다시 원하는 relra.plt주소를 획득,
이후 relra.plt구조체를 통해 dynsym을 획득한후,
dynstr주소를 획득하여 필요한 모든 주소를 구한후,
_dl_lookup_symbol_x 함수에 넘기는것을 알 수 있다.

## _dl_lookup_symbol_x
이제 진ㅉ


# Ret2dlresolve
이제 대강 분석을 해봤으니 ret2dlresolve를 직접 익스플로잇 해보자.
