//! One-byte opcode map and x87 (see tables.rs for the grammar).

pub(crate) const SPEC: &str = r#"
# ------------------------------------------------------------------ ALU 00-3f
1 00 : add m:b, r:b ; lock
1 01 : add m:v, r:v ; lock
1 02 : add r:b, m:b ; lock
1 03 : add r:v, m:v ; lock
1 04 : add al, i:b
1 05 : add eAX, i:z
1 06 mode32 : push es
1 07 mode32 : pop es
1 08 : or m:b, r:b ; lock
1 09 : or m:v, r:v ; lock
1 0a : or r:b, m:b ; lock
1 0b : or r:v, m:v ; lock
1 0c : or al, i:b
1 0d : or eAX, i:z ; immu
1 0e mode32 : push cs
1 10 : adc m:b, r:b ; lock
1 11 : adc m:v, r:v ; lock
1 12 : adc r:b, m:b ; lock
1 13 : adc r:v, m:v ; lock
1 14 : adc al, i:b
1 15 : adc eAX, i:z
1 16 mode32 : push ss
1 17 mode32 : pop ss
1 18 : sbb m:b, r:b ; lock
1 19 : sbb m:v, r:v ; lock
1 1a : sbb r:b, m:b
1 1b : sbb r:v, m:v
1 1c : sbb al, i:b
1 1d : sbb eAX, i:z
1 1e mode32 : push ds
1 1f mode32 : pop ds
1 20 : and m:b, r:b ; lock
1 21 : and m:v, r:v ; lock
1 22 : and r:b, m:b ; lock
1 23 : and r:v, m:v ; lock
1 24 : and al, i:b
1 25 : and eAX, i:z ; immu
1 27 mode32 : daa
1 28 : sub m:b, r:b ; lock
1 29 : sub m:v, r:v ; lock
1 2a : sub r:b, m:b ; lock
1 2b : sub r:v, m:v ; lock
1 2c : sub al, i:b
1 2d : sub eAX, i:z
1 2f mode32 : das
1 30 : xor m:b, r:b ; lock
1 31 : xor m:v, r:v ; lock
1 32 : xor r:b, m:b ; lock
1 33 : xor r:v, m:v ; lock
1 34 : xor al, i:b
1 35 : xor eAX, i:z ; immu
1 37 mode32 : aaa
1 38 : cmp m:b, r:b
1 39 : cmp m:v, r:v
1 3a : cmp r:b, m:b
1 3b : cmp r:v, m:v
1 3c : cmp al, i:b
1 3d : cmp eAX, i:z
1 3f mode32 : aas
# ------------------------------------------------------------------ 40-6f
1 40-47 mode32 : inc o:v
1 48-4f mode32 : dec o:v
1 50-57 : push o:v ; d64
1 58-5f : pop o:v ; d64
1 60 mode32 o16 : pushaw
1 60 mode32 o32 : pushal
1 61 mode32 o16 : popaw
1 61 mode32 o32 : popal
1 62 mode32 m o16 : bound r:w, M:/d
1 62 mode32 m o32 : bound r:d, M:/q
1 63 mode32 : arpl m:w, r:w
1 63 mode64 : movsxd r:v, m:d
1 63 mode64 a32 w0 : INVALID
1 68 : push i:z ; d64
1 68 mode64 p66 w1 : push i:d
1 69 : imul r:v, m:v, i:z
1 6a : push i:bn ; d64
1 6b : imul r:v, m:v, i:bs
1 6c : insb D:b, dx ; rep
1 6d p66 : insw D:w, dx ; rep
1 6d n66 : insd D:d, dx ; rep
1 6e : outsb dx, S:b ; rep
1 6f p66 : outsw dx, S:w ; rep
1 6f n66 : outsd dx, S:d ; rep
# ------------------------------------------------------------------ 70-7f
1 70 : jo j:b ; bnd f64
1 71 : jno j:b ; bnd f64
1 72 : jb j:b ; bnd f64
1 73 : jae j:b ; bnd f64
1 74 : je j:b ; bnd f64
1 75 : jne j:b ; bnd f64
1 76 : jbe j:b ; bnd f64
1 77 : ja j:b ; bnd f64
1 78 : js j:b ; bnd f64
1 79 : jns j:b ; bnd f64
1 7a : jp j:b ; bnd f64
1 7b : jnp j:b ; bnd f64
1 7c : jl j:b ; bnd f64
1 7d : jge j:b ; bnd f64
1 7e : jle j:b ; bnd f64
1 7f : jg j:b ; bnd f64
# ------------------------------------------------------------------ 80-8f
1 80 /0 : add m:b, i:b ; lock
1 80 /1 : or m:b, i:b ; lock
1 80 /2 : adc m:b, i:b ; lock
1 80 /3 : sbb m:b, i:b ; lock
1 80 /4 : and m:b, i:b ; lock
1 80 /5 : sub m:b, i:b ; lock
1 80 /6 : xor m:b, i:b ; lock
1 80 /7 : cmp m:b, i:b
1 82 mode32 /0 : add m:b, i:b ; lock
1 82 mode32 /1 : or m:b, i:b ; lock
1 82 mode32 /2 : adc m:b, i:b ; lock
1 82 mode32 /3 : sbb m:b, i:b ; lock
1 82 mode32 /4 : and m:b, i:b ; lock
1 82 mode32 /5 : sub m:b, i:b ; lock
1 82 mode32 /6 : xor m:b, i:b ; lock
1 82 mode32 /7 : cmp m:b, i:b
1 81 /0 : add m:v, i:z ; lock
1 81 /1 : or m:v, i:z ; lock immu
1 81 /2 : adc m:v, i:z ; lock
1 81 /3 : sbb m:v, i:z ; lock
1 81 /4 : and m:v, i:z ; lock immu
1 81 /5 : sub m:v, i:z ; lock
1 81 /6 : xor m:v, i:z ; lock immu
1 81 /7 : cmp m:v, i:z
1 83 /0 : add m:v, i:bs ; lock
1 83 /1 : or m:v, i:bs ; lock immu
1 83 /2 : adc m:v, i:bs ; lock
1 83 /3 : sbb m:v, i:bs ; lock
1 83 /4 : and m:v, i:bs ; lock immu
1 83 /5 : sub m:v, i:bs ; lock
1 83 /6 : xor m:v, i:bs ; lock immu
1 83 /7 : cmp m:v, i:bs
1 84 : test m:b, r:b
1 85 : test m:v, r:v
1 86 : xchg m:b, r:b ; lock xa
1 87 : xchg m:v, r:v ; lock xa
1 88 : mov m:b, r:b
1 89 : mov m:v, r:v
1 8a : mov r:b, m:b
1 8b : mov r:v, m:v
1 8c : mov m:v/w, r:s
1 8d : lea r:v, M:
1 8e : mov r:s, m:v/w
1 8f /0 : pop m:v ; d64
# ------------------------------------------------------------------ 90-9f
1 90 : nop
1 90 rexb1 : xchg o:v, eAX
1 90 f3 rexb0 o32 : pause
1 90 f3 rexb0 o16 : INVALID
1 90 f3 rexb0 o64 : xchg o:v, eAX
1 91-97 : xchg o:v, eAX
1 98 o16 : cbw
1 98 o32 : cwde
1 98 o64 : cdqe
1 99 o16 : cwd
1 99 o32 : cdq
1 99 o64 : cqo
1 9a mode32 : lcall farc
1 9b : wait
1 9c p66 : pushf
1 9c n66 mode32 : pushfd
1 9c n66 mode64 : pushfq
1 9d p66 : popf
1 9d n66 mode32 : popfd
1 9d n66 mode64 : popfq
1 9e : sahf
1 9f : lahf
# ------------------------------------------------------------------ a0-af
1 a0 a16|a32 : mov al, a:b
1 a0 a64 : movabs al, a:b
1 a0 a32 mode64 w1 : movabs al, a:b
1 a1 a16|a32 : mov eAX, a:v
1 a1 a64 : movabs eAX, a:v
1 a2 a16|a32 : mov a:b, al
1 a2 a64 : movabs a:b, al
1 a2 a32 mode64 w1 : movabs a:b, al
1 a3 a16|a32 : mov a:v, eAX
1 a3 a64 : movabs a:v, eAX
1 a4 : movsb D:b, S:b ; rep
1 a5 o16 : movsw D:w, S:w ; rep
1 a5 o32 : movsd D:d, S:d ; repf3
1 a5 o64 : movsq D:q, S:q ; rep
1 a6 : cmpsb S:b, D:b ; repe
1 a7 o16 : cmpsw S:w, D:w ; repe
1 a7 o32 : cmpsd S:d, D:d ; repe
1 a7 o64 : cmpsq S:q, D:q ; repe
1 a8 : test al, i:b
1 a9 : test eAX, i:z
1 aa : stosb D:b, al ; rep
1 ab o16 : stosw D:w, ax ; rep
1 ab o32 : stosd D:d, eax ; rep
1 ab o64 : stosq D:q, rax ; rep
1 ac : lodsb al, S:b ; rep
1 ad o16 : lodsw ax, S:w ; rep
1 ad o32 : lodsd eax, S:d ; rep
1 ad o64 : lodsq rax, S:q ; rep
1 ae : scasb al, D:b ; repe
1 af o16 : scasw ax, D:w ; repe
1 af o32 : scasd eax, D:d ; repe
1 af o64 : scasq rax, D:q ; repe
# ------------------------------------------------------------------ b0-bf
1 b0-b7 : mov o:b, i:b
1 b8-bf o16|o32 : mov o:v, i:v
1 b8-bf o64 : movabs o:v, i:v
# ------------------------------------------------------------------ c0-cf
1 c0 /0 : rol m:b, i:b
1 c0 /1 : ror m:b, i:b
1 c0 /2 : rcl m:b, i:b
1 c0 /3 : rcr m:b, i:b
1 c0 /4 : shl m:b, i:b
1 c0 /5 : shr m:b, i:b
1 c0 /6 : sal m:b, i:b
1 c0 /7 : sar m:b, i:b
1 c1 /0 : rol m:v, i:b
1 c1 /1 : ror m:v, i:b
1 c1 /2 : rcl m:v, i:b
1 c1 /3 : rcr m:v, i:b
1 c1 /4 : shl m:v, i:b
1 c1 /5 : shr m:v, i:b
1 c1 /6 : sal m:v, i:b
1 c1 /7 : sar m:v, i:b
1 c2 : ret i:w ; bnd repz f64
1 c2 mode64 p66 w1 : ret i:w4 ; bnd repz f64
1 c3 : ret ; bnd repz f64
1 c4 mode32 m : les r:v, M:/p
1 c5 mode32 m : lds r:v, M:/p
1 c6 /0 : mov m:b, i:b
1 c6 @f8 : xabort i:bs
1 c7 /0 : mov m:v, i:z ; immu
1 c7 @f8 : xbegin j:z
1 c8 : enter i:ws, i:bs ; d64
1 c9 : leave ; d64
1 ca o16|o32 : retf i:w ; bnd
1 ca o64 : retfq i:ws ; bnd
1 cb o16|o32 : retf ; bnd
1 cb o64 : retfq ; bnd
1 cc : int3
1 cd : int i:b
1 ce mode32 : into
1 cf o16 : iret
1 cf o32 : iretd
1 cf o64 : iretq
# ------------------------------------------------------------------ d0-df
1 d0 /0 : rol m:b, 1
1 d0 /1 : ror m:b, 1
1 d0 /2 m : rcl m:b
1 d0 /2 r : rcl m:b, 1
1 d0 /3 : rcr m:b, 1
1 d0 /4 : shl m:b, 1
1 d0 /5 : shr m:b, 1
1 d0 /6 : sal m:b, 1
1 d0 /7 : sar m:b, 1
1 d1 /0 : rol m:v, 1
1 d1 /1 : ror m:v, 1
1 d1 /2 m : rcl m:v
1 d1 /2 r : rcl m:v, 1
1 d1 /3 : rcr m:v, 1
1 d1 /4 : shl m:v, 1
1 d1 /5 : shr m:v, 1
1 d1 /6 : sal m:v, 1
1 d1 /7 : sar m:v, 1
1 d2 /0 : rol m:b, cl
1 d2 /1 : ror m:b, cl
1 d2 /2 : rcl m:b, cl
1 d2 /3 : rcr m:b, cl
1 d2 /4 : shl m:b, cl
1 d2 /5 : shr m:b, cl
1 d2 /6 : sal m:b, cl
1 d2 /7 : sar m:b, cl
1 d3 /0 : rol m:v, cl
1 d3 /1 : ror m:v, cl
1 d3 /2 : rcl m:v, cl
1 d3 /3 : rcr m:v, cl
1 d3 /4 : shl m:v, cl
1 d3 /5 : shr m:v, cl
1 d3 /6 : sal m:v, cl
1 d3 /7 : sar m:v, cl
1 d4 mode32 : aam i:b
1 d5 mode32 : aad i:b
1 d6 mode32 : salc
1 d7 : xlatb
# x87 d8
1 d8 m /0 : fadd M:/d
1 d8 m /1 : fmul M:/d
1 d8 m /2 : fcom M:/d
1 d8 m /3 : fcomp M:/d
1 d8 m /4 : fsub M:/d
1 d8 m /5 : fsubr M:/d
1 d8 m /6 : fdiv M:/d
1 d8 m /7 : fdivr M:/d
1 d8 r /0 : fadd R:st
1 d8 r /1 : fmul R:st
1 d8 r /2 : fcom R:st
1 d8 r /3 : fcomp R:st
1 d8 r /4 : fsub R:st
1 d8 r /5 : fsubr R:st
1 d8 r /6 : fdiv R:st
1 d8 r /7 : fdivr R:st
# d9
1 d9 m /0 : fld M:/d
1 d9 m /2 : fst M:/d
1 d9 m /3 : fstp M:/d
1 d9 m /4 : fldenv M:/n
1 d9 m /5 : fldcw M:/w
1 d9 m /6 : fnstenv M:/n
1 d9 m /7 : fnstcw M:/w
1 d9 r /0 : fld R:st
1 d9 r /1 : fxch R:st
1 d9 r /3 : fstpnce R:st, st0
1 d9 @d0 : fnop
1 d9 @e0 : fchs
1 d9 @e1 : fabs
1 d9 @e4 : ftst
1 d9 @e5 : fxam
1 d9 @e8 : fld1
1 d9 @e9 : fldl2t
1 d9 @ea : fldl2e
1 d9 @eb : fldpi
1 d9 @ec : fldlg2
1 d9 @ed : fldln2
1 d9 @ee : fldz
1 d9 @f0 : f2xm1
1 d9 @f1 : fyl2x
1 d9 @f2 : fptan
1 d9 @f3 : fpatan
1 d9 @f4 : fxtract
1 d9 @f5 : fprem1
1 d9 @f6 : fdecstp
1 d9 @f7 : fincstp
1 d9 @f8 : fprem
1 d9 @f9 : fyl2xp1
1 d9 @fa : fsqrt
1 d9 @fb : fsincos
1 d9 @fc : frndint
1 d9 @fd : fscale
1 d9 @fe : fsin
1 d9 @ff : fcos
# da
1 da m /0 : fiadd M:/d
1 da m /1 : fimul M:/d
1 da m /2 : ficom M:/d
1 da m /3 : ficomp M:/d
1 da m /4 : fisub M:/d
1 da m /5 : fisubr M:/d
1 da m /6 : fidiv M:/d
1 da m /7 : fidivr M:/d
1 da r /0 : fcmovb st0, R:st
1 da r /1 : fcmove st0, R:st
1 da r /2 : fcmovbe st0, R:st
1 da r /3 : fcmovu st0, R:st
1 da @e9 : fucompp
# db
1 db m /0 : fild M:/d
1 db m /1 : fisttp M:/d
1 db m /2 : fist M:/d
1 db m /3 : fistp M:/d
1 db m /5 : fld M:/xw
1 db m /7 : fstp M:/xw
1 db r /0 : fcmovnb st0, R:st
1 db r /1 : fcmovne st0, R:st
1 db r /2 : fcmovnbe st0, R:st
1 db r /3 : fcmovnu st0, R:st
1 db @e0 : feni8087_nop
1 db @e1 : fdisi8087_nop
1 db @e2 : fnclex
1 db @e3 : fninit
1 db @e4 : fsetpm
1 db r /5 : fucomi R:st
1 db r /6 : fcomi R:st
# dc
1 dc m /0 : fadd M:/q
1 dc m /1 : fmul M:/q
1 dc m /2 : fcom M:/q
1 dc m /3 : fcomp M:/q
1 dc m /4 : fsub M:/q
1 dc m /5 : fsubr M:/q
1 dc m /6 : fdiv M:/q
1 dc m /7 : fdivr M:/q
1 dc r /0 : fadd R:st, st0
1 dc r /1 : fmul R:st, st0
1 dc r /4 : fsubr R:st, st0
1 dc r /5 : fsub R:st, st0
1 dc r /6 : fdivr R:st, st0
1 dc r /7 : fdiv R:st, st0
# dd
1 dd m /0 : fld M:/q
1 dd m /1 : fisttp M:/q
1 dd m /2 : fst M:/q
1 dd m /3 : fstp M:/q
1 dd m /4 : frstor M:/d
1 dd m /6 : fnsave M:/d
1 dd m /7 : fnstsw M:/w
1 dd r /0 : ffree R:st
1 dd r /2 : fst R:st
1 dd r /3 : fstp R:st
1 dd r /4 : fucom R:st
1 dd r /5 : fucomp R:st
# de
1 de m /0 : fiadd M:/w
1 de m /1 : fimul M:/w
1 de m /2 : ficom M:/w
1 de m /3 : ficomp M:/w
1 de m /4 : fisub M:/w
1 de m /5 : fisubr M:/w
1 de m /6 : fidiv M:/w
1 de m /7 : fidivr M:/w
1 de r /0 : faddp R:st
1 de r /1 : fmulp R:st
1 de @d9 : fcompp
1 de r /4 : fsubrp R:st
1 de r /5 : fsubp R:st
1 de r /6 : fdivrp R:st
1 de r /7 : fdivp R:st
# df
1 df m /0 : fild M:/w
1 df m /1 : fisttp M:/w
1 df m /2 : fist M:/w
1 df m /3 : fistp M:/w
1 df m /4 : fbld M:/t
1 df m /5 : fild M:/q
1 df m /6 : fbstp M:/t
1 df m /7 : fistp M:/q
1 df r /0 : ffreep R:st
1 df @e0 : fnstsw ax
1 df r /5 : fucompi R:st
1 df r /6 : fcompi R:st
# ------------------------------------------------------------------ e0-ff
1 e0 : loopne j:b ; f64
1 e1 : loope j:b ; f64
1 e2 : loop j:b ; f64
1 e3 a16 : jcxz j:b ; bnd f64
1 e3 a32 : jecxz j:b ; bnd f64
1 e3 a32 mode64 o16|o64 : jrcxz j:b ; bnd f64
1 e3 a64 : jrcxz j:b ; bnd f64
1 e4 : in al, i:b
1 e5 : in zAX, i:b ; z66
1 e6 : out i:b, al
1 e7 : out i:b, zAX ; z66
1 e8 : call j:z ; bnd f64 notrack
1 e9 : jmp j:z ; bnd f64 notrack relq
1 ea mode32 : ljmp far
1 eb : jmp j:b ; bnd f64 notrack
1 ec : in al, dx
1 ed : in zAX, dx ; z66
1 ee : out dx, al
1 ef : out dx, zAX ; z66
1 f1 : int1
1 f4 : hlt
1 f5 : cmc
1 f6 /0 : test m:b, i:b
1 f6 /1 : test m:b, i:bs
1 f6 /2 : not m:b ; lock
1 f6 /3 : neg m:b ; lock
1 f6 /4 : mul m:b
1 f6 /5 : imul m:b
1 f6 /6 : div m:b
1 f6 /7 : idiv m:b
1 f7 /0 : test m:v, i:z
1 f7 /1 : test m:v, i:z
1 f7 /2 : not m:v ; lock
1 f7 /3 : neg m:v ; lock
1 f7 /4 : mul m:v
1 f7 /5 : imul m:v
1 f7 /6 : div m:v
1 f7 /7 : idiv m:v
1 f8 : clc
1 f9 : stc
1 fa : cli
1 fb : sti
1 fc : cld
1 fd : std
1 fe /0 : inc m:b ; lock
1 fe /1 : dec m:b ; lock
1 ff /0 : inc m:v ; lock
1 ff /1 : dec m:v ; lock
1 ff /2 : call m:v ; bnd notrack f64
1 ff /3 m o32 : call M:/p ; bnd notrack
1 ff /3 m o16|o64 : lcall M:/n
1 ff /4 : jmp m:v ; bnd notrack f64
1 ff /5 m o32 : jmp M:/p ; bnd notrack
1 ff /5 m o16|o64 : ljmp M:/n
1 ff /6 : push m:v ; d64
"#;
