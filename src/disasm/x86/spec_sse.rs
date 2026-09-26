//! Two- and three-byte legacy opcode maps (0F, 0F38, 0F3A, 3DNow!).

pub(crate) const SPEC: &str = r#"
# ------------------------------------------------------------------ 0F 00-0F
0f 00 /0 : sldt m:v/w
0f 00 /1 : str m:v/w
0f 00 /2 : lldt m:w
0f 00 /3 : ltr m:w
0f 00 /4 : verr m:w
0f 00 /5 : verw m:w
0f 01 m /0 : sgdt M:
0f 01 m /1 : sidt M:
0f 01 m /2 : lgdt M:
0f 01 m /3 : lidt M:
0f 01 /4 : smsw m:v/w
0f 01 /6 : lmsw m:w
0f 01 m /7 : invlpg M:/b
0f 01 @c0 : enclv
0f 01 @c1 : vmcall
0f 01 @c2 : vmlaunch
0f 01 @c3 : vmresume
0f 01 @c4 : vmxoff
0f 01 @c5 : pconfig
0f 01 @c8 : monitor
0f 01 @c9 : mwait
0f 01 @ca : clac
0f 01 @cb : stac
0f 01 @cf : encls
0f 01 @d0 : xgetbv
0f 01 @d1 : xsetbv
0f 01 @d4 : vmfunc
0f 01 @d5 : xend
0f 01 @d6 : xtest
0f 01 @d7 : enclu
0f 01 @d8 : vmrun aAX
0f 01 @d9 : vmmcall
0f 01 @da : vmload aAX
0f 01 @db : vmsave aAX
0f 01 @dc : stgi
0f 01 @dd : clgi
0f 01 @de : skinit eax
0f 01 @df : invlpga aAX, ecx
0f 01 @ee : rdpkru
0f 01 @ef : wrpkru
0f 01 @f8 : swapgs
0f 01 @f9 : rdtscp
0f 01 @fa : monitorx
0f 01 @fb : mwaitx
0f 01 @fc : clzero
0f 02 : lar r:v, m:z/w
0f 03 : lsl r:v, m:z/w
0f 05 : syscall
0f 06 : clts
0f 07 w0 : sysret
0f 07 w1 : sysretq
0f 08 : invd
0f 09 : wbinvd
0f 09 f3 : wbnoinvd
0f 0b : ud2
0f 0d m /0 : prefetch M:/b
0f 0d m /1 : prefetchw M:/b
0f 0d m /2 : prefetchwt1 M:/b
0f 0e : femms
# ------------------------------------------------------------------ 0F 10-17
0f 10 np : movups r:x, m:x
0f 10 66 : movupd r:x, m:x
0f 10 f3 : movss r:x, m:x/d
0f 10 f2 : movsd r:x, m:x/q
0f 11 np : movups m:x, r:x
0f 11 66 : movupd m:x, r:x
0f 11 f3 : movss m:x/d, r:x
0f 11 f2 : movsd m:x/q, r:x
0f 12 np m : movlps r:x, M:/q
0f 12 np r : movhlps r:x, R:x
0f 12 66 m : movlpd r:x, M:/q
0f 12 f3 : movsldup r:x, m:x
0f 12 f2 : movddup r:x, m:x/q
0f 13 np m : movlps M:/q, r:x
0f 13 66 m : movlpd M:/q, r:x
0f 14 np : unpcklps r:x, m:x
0f 14 66 : unpcklpd r:x, m:x
0f 15 np : unpckhps r:x, m:x
0f 15 66 : unpckhpd r:x, m:x
0f 16 np m : movhps r:x, M:/q
0f 16 np r : movlhps r:x, R:x
0f 16 66 m : movhpd r:x, M:/q
0f 16 f3 : movshdup r:x, m:x
0f 17 np m : movhps M:/q, r:x
0f 17 66 m : movhpd M:/q, r:x
# ------------------------------------------------------------------ 0F 18-1F
0f 18 m /0 : prefetchnta M:/b
0f 18 m /1 : prefetcht0 M:/b
0f 18 m /2 : prefetcht1 M:/b
0f 18 m /3 : prefetcht2 M:/b
0f 18 /4-7 : nop m:v/z
0f 19 m : nop m:v/z
0f 19 r : nop m:v, r:v
0f 1a np m : bndldx r:bnd, M:
0f 1a 66 mode64 : bndmov r:bnd, m:bnd/x
0f 1a 66 mode32 : bndmov r:bnd, m:bnd/q
0f 1a f3 : bndcl r:bnd, m:n/n
0f 1a f2 : bndcu r:bnd, m:n/n
0f 1b np m : bndstx M:, r:bnd
0f 1b 66 mode64 : bndmov m:bnd/x, r:bnd
0f 1b 66 mode32 : bndmov m:bnd/q, r:bnd
0f 1b f3 m : bndmk r:bnd, M:
0f 1b f2 : bndcn r:bnd, m:n/n
0f 1c np|f3|f2 m /0 : cldemote M:/b
0f 1c 66 m : nop m:v/z
0f 1d m : nop m:v/z
0f 1e m : nop m:v/z
0f 1f o32|o64 : nop m:v ; lock
0f 1f o16 : nop m:v
# ------------------------------------------------------------------ 0F 20-2F
0f 20 : mov R:n, r:c ; regform
0f 21 : mov R:n, r:dr ; regform
0f 22 : mov r:c, R:n ; regform
0f 23 : mov r:dr, R:n ; regform
0f 28 np : movaps r:x, m:x
0f 28 66 : movapd r:x, m:x
0f 29 np : movaps m:x, r:x
0f 29 66 : movapd m:x, r:x
0f 2a np : cvtpi2ps r:x, m:mm
0f 2a 66 : cvtpi2pd r:x, m:mm
0f 2a f3 : cvtsi2ss r:x, m:y
0f 2a f2 : cvtsi2sd r:x, m:y
0f 2b np m : movntps M:/x, r:x
0f 2b 66 m : movntpd M:/x, r:x
0f 2b f3 m : movntss M:/d, r:x
0f 2b f2 m : movntsd M:/q, r:x
0f 2c np : cvttps2pi r:mm, m:x/q
0f 2c 66 : cvttpd2pi r:mm, m:x
0f 2c f3 : cvttss2si r:y, m:x/d
0f 2c f2 : cvttsd2si r:y, m:x/q
0f 2d np : cvtps2pi r:mm, m:x/q
0f 2d 66 : cvtpd2pi r:mm, m:x
0f 2d f3 : cvtss2si r:y, m:x/d
0f 2d f2 : cvtsd2si r:y, m:x/q
0f 2e np : ucomiss r:x, m:x/d
0f 2e 66 : ucomisd r:x, m:x/q
0f 2f np : comiss r:x, m:x/d
0f 2f 66 : comisd r:x, m:x
# ------------------------------------------------------------------ 0F 30-3F
0f 30 : wrmsr
0f 31 : rdtsc
0f 32 : rdmsr
0f 33 : rdpmc
0f 34 : sysenter
0f 35 w0 : sysexit
0f 35 w1 : sysexitq
0f 37 : getsec
# ------------------------------------------------------------------ 0F 40-4F cmovcc
0f 40 : cmovo r:v, m:v
0f 41 : cmovno r:v, m:v
0f 42 : cmovb r:v, m:v
0f 43 : cmovae r:v, m:v
0f 44 : cmove r:v, m:v
0f 45 : cmovne r:v, m:v
0f 46 : cmovbe r:v, m:v
0f 47 : cmova r:v, m:v
0f 48 : cmovs r:v, m:v
0f 49 : cmovns r:v, m:v
0f 4a : cmovp r:v, m:v
0f 4b : cmovnp r:v, m:v
0f 4c : cmovl r:v, m:v
0f 4d : cmovge r:v, m:v
0f 4e : cmovle r:v, m:v
0f 4f : cmovg r:v, m:v
# ------------------------------------------------------------------ 0F 50-5F
0f 50 np r : movmskps r:d, R:x
0f 50 66 r : movmskpd r:d, R:x
0f 51 np : sqrtps r:x, m:x
0f 51 66 : sqrtpd r:x, m:x
0f 51 f3 : sqrtss r:x, m:x/d
0f 51 f2 : sqrtsd r:x, m:x/q
0f 52 np : rsqrtps r:x, m:x
0f 52 f3 : rsqrtss r:x, m:x/d
0f 53 np : rcpps r:x, m:x
0f 53 f3 : rcpss r:x, m:x/d
0f 54 np : andps r:x, m:x
0f 54 66 : andpd r:x, m:x
0f 55 np : andnps r:x, m:x
0f 55 66 : andnpd r:x, m:x
0f 56 np : orps r:x, m:x
0f 56 66 : orpd r:x, m:x
0f 57 np : xorps r:x, m:x
0f 57 66 : xorpd r:x, m:x
0f 58 np : addps r:x, m:x
0f 58 66 : addpd r:x, m:x
0f 58 f3 : addss r:x, m:x/d
0f 58 f2 : addsd r:x, m:x/q
0f 59 np : mulps r:x, m:x
0f 59 66 : mulpd r:x, m:x
0f 59 f3 : mulss r:x, m:x/d
0f 59 f2 : mulsd r:x, m:x/q
0f 5a np : cvtps2pd r:x, m:x/q
0f 5a 66 : cvtpd2ps r:x, m:x
0f 5a f3 : cvtss2sd r:x, m:x/d
0f 5a f2 : cvtsd2ss r:x, m:x/q
0f 5b np : cvtdq2ps r:x, m:x
0f 5b 66 : cvtps2dq r:x, m:x
0f 5b f3 : cvttps2dq r:x, m:x
0f 5c np : subps r:x, m:x
0f 5c 66 : subpd r:x, m:x
0f 5c f3 : subss r:x, m:x/d
0f 5c f2 : subsd r:x, m:x/q
0f 5d np : minps r:x, m:x
0f 5d 66 : minpd r:x, m:x
0f 5d f3 : minss r:x, m:x/d
0f 5d f2 : minsd r:x, m:x/q
0f 5e np : divps r:x, m:x
0f 5e 66 : divpd r:x, m:x
0f 5e f3 : divss r:x, m:x/d
0f 5e f2 : divsd r:x, m:x/q
0f 5f np : maxps r:x, m:x
0f 5f 66 : maxpd r:x, m:x
0f 5f f3 : maxss r:x, m:x/d
0f 5f f2 : maxsd r:x, m:x/q
# ------------------------------------------------------------------ 0F 60-6F
0f 60 np : punpcklbw r:mm, m:mm/d
0f 60 66 : punpcklbw r:x, m:x
0f 61 np : punpcklwd r:mm, m:mm/d
0f 61 66 : punpcklwd r:x, m:x
0f 62 np : punpckldq r:mm, m:mm/d
0f 62 66 : punpckldq r:x, m:x
0f 63 np : packsswb r:mm, m:mm
0f 63 66 : packsswb r:x, m:x
0f 64 np : pcmpgtb r:mm, m:mm
0f 64 66 : pcmpgtb r:x, m:x
0f 65 np : pcmpgtw r:mm, m:mm
0f 65 66 : pcmpgtw r:x, m:x
0f 66 np : pcmpgtd r:mm, m:mm
0f 66 66 : pcmpgtd r:x, m:x
0f 67 np : packuswb r:mm, m:mm
0f 67 66 : packuswb r:x, m:x
0f 68 np : punpckhbw r:mm, m:mm
0f 68 66 : punpckhbw r:x, m:x
0f 69 np : punpckhwd r:mm, m:mm
0f 69 66 : punpckhwd r:x, m:x
0f 6a np : punpckhdq r:mm, m:mm
0f 6a 66 : punpckhdq r:x, m:x
0f 6b np : packssdw r:mm, m:mm
0f 6b 66 : packssdw r:x, m:x
0f 6c 66 : punpcklqdq r:x, m:x
0f 6d 66 : punpckhqdq r:x, m:x
0f 6e np w0 : movd r:mm, m:d
0f 6e np w1 : movq r:mm, m:q
0f 6e 66 w0 : movd r:x, m:d
0f 6e 66 w1 : movq r:x, m:q
0f 6f np : movq r:mm, m:mm
0f 6f 66 : movdqa r:x, m:x
0f 6f f3 : movdqu r:x, m:x
# ------------------------------------------------------------------ 0F 70-7F
0f 70 np : pshufw r:mm, m:mm, i:b
0f 70 66 : pshufd r:x, m:x, i:b
0f 70 f3 : pshufhw r:x, m:x, i:b
0f 70 f2 : pshuflw r:x, m:x, i:b
0f 71 np r /2 : psrlw R:mm, i:b
0f 71 np r /4 : psraw R:mm, i:b
0f 71 np r /6 : psllw R:mm, i:b
0f 71 66 r /2 : psrlw R:x, i:b
0f 71 66 r /4 : psraw R:x, i:b
0f 71 66 r /6 : psllw R:x, i:b
0f 72 np r /2 : psrld R:mm, i:b
0f 72 np r /4 : psrad R:mm, i:b
0f 72 np r /6 : pslld R:mm, i:b
0f 72 66 r /2 : psrld R:x, i:b
0f 72 66 r /4 : psrad R:x, i:b
0f 72 66 r /6 : pslld R:x, i:b
0f 73 np r /2 : psrlq R:mm, i:b
0f 73 np r /6 : psllq R:mm, i:b
0f 73 66 r /2 : psrlq R:x, i:b
0f 73 66 r /3 : psrldq R:x, i:b
0f 73 66 r /6 : psllq R:x, i:b
0f 73 66 r /7 : pslldq R:x, i:b
0f 74 np : pcmpeqb r:mm, m:mm
0f 74 66 : pcmpeqb r:x, m:x
0f 75 np : pcmpeqw r:mm, m:mm
0f 75 66 : pcmpeqw r:x, m:x
0f 76 np : pcmpeqd r:mm, m:mm
0f 76 66 : pcmpeqd r:x, m:x
0f 77 np : emms
0f 78 np : vmread m:n, r:n
0f 78 66 r : extrq R:x, i:b, i:b
0f 78 f2 r : insertq r:x, R:x, i:b, i:b
0f 79 np : vmwrite r:n, m:n
0f 79 66 r : extrq r:x, R:x
0f 79 f2 r : insertq r:x, R:x
0f 7c 66 : haddpd r:x, m:x
0f 7c f2 : haddps r:x, m:x
0f 7d 66 : hsubpd r:x, m:x
0f 7d f2 : hsubps r:x, m:x
0f 7e np w0 : movd m:d, r:mm
0f 7e np w1 : movq m:q, r:mm
0f 7e 66 w0 : movd m:d, r:x
0f 7e 66 w1 : movq m:q, r:x
0f 7e f3 : movq r:x, m:x/q
0f 7f np : movq m:mm, r:mm
0f 7f 66 : movdqa m:x, r:x
0f 7f f3 : movdqu m:x, r:x
# ------------------------------------------------------------------ 0F 80-8F jcc
0f 80 : jo j:z ; bnd d64 relq
0f 81 : jno j:z ; bnd d64 relq
0f 82 : jb j:z ; bnd f64 relq
0f 83 : jae j:z ; bnd f64 relq
0f 84 : je j:z ; bnd f64 relq
0f 85 : jne j:z ; bnd f64 relq
0f 86 : jbe j:z ; bnd f64 relq
0f 87 : ja j:z ; bnd f64 relq
0f 88 : js j:z ; bnd f64 relq
0f 89 : jns j:z ; bnd f64 relq
0f 8a : jp j:z ; bnd f64 relq
0f 8b : jnp j:z ; bnd f64 relq
0f 8c : jl j:z ; bnd f64 relq
0f 8d : jge j:z ; bnd f64 relq
0f 8e : jle j:z ; bnd f64 relq
0f 8f : jg j:z ; bnd f64 relq
0f 82-8f mode64 f3|f2 p66 w0 : INVALID
# ------------------------------------------------------------------ 0F 90-9F setcc
0f 90 : seto m:b
0f 91 : setno m:b
0f 92 : setb m:b
0f 93 : setae m:b
0f 94 : sete m:b
0f 95 : setne m:b
0f 96 : setbe m:b
0f 97 : seta m:b
0f 98 : sets m:b
0f 99 : setns m:b
0f 9a : setp m:b
0f 9b : setnp m:b
0f 9c : setl m:b
0f 9d : setge m:b
0f 9e : setle m:b
0f 9f : setg m:b
# ------------------------------------------------------------------ 0F A0-AF
0f a0 : push fs ; d64
0f a1 : pop fs ; d64
0f a2 : cpuid
0f a3 : bt m:v, r:v
0f a4 : shld m:v, r:v, i:b
0f a5 : shld m:v, r:v, cl
0f a6 @c0 : montmul
0f a6 @c8 : xsha1
0f a6 @d0 : xsha256
0f a7 @c0 : xstore
0f a7 @c8 : xcryptecb
0f a7 @d0 : xcryptcbc
0f a7 @d8 : xcryptctr
0f a7 @e0 : xcryptcfb
0f a7 @e8 : xcryptofb
0f a8 : push gs ; d64
0f a9 : pop gs ; d64
0f aa : rsm
0f ab : bts m:v, r:v ; lock
0f ac : shrd m:v, r:v, i:b
0f ad : shrd m:v, r:v, cl
0f ae m /0 np|66|f3|f2 w0 : fxsave M:
0f ae m /0 np|66|f3|f2 w1 : fxsave64 M:/p
0f ae m /1 np|66|f3|f2 w0 : fxrstor M:
0f ae m /1 np|66|f3|f2 w1 : fxrstor64 M:/p
0f ae m /2 np|66|f3|f2 : ldmxcsr M:/d
0f ae m /3 np|66|f3|f2 : stmxcsr M:/d
0f ae np m /4 w0 : xsave M:/p
0f ae np m /4 w1 : xsave64 M:/p
0f ae np m /5 w0 : xrstor M:/p
0f ae np m /5 w1 : xrstor64 M:/p
0f ae np m /6 w0 : xsaveopt M:/p
0f ae np m /6 w1 : xsaveopt64 M:/p
0f ae np m /7 : clflush M:/b
0f ae np @e8 : lfence
0f ae np @f0 : mfence
0f ae np @f8 : sfence
0f ae f3|f2 p66 w0 : INVALID
0f ae 66 m /6 : clwb M:/b
0f ae 66 m /7 : clflushopt M:/b
0f ae 66 r /6 : tpause R:d
0f ae f3 r /6 : umonitor R:A
0f ae f2 r /6 : umwait R:d
0f ae f3 mode64 r /0 : rdfsbase R:y
0f ae f3 mode64 r /1 : rdgsbase R:y
0f ae f3 mode64 r /2 : wrfsbase R:y
0f ae f3 mode64 r /3 : wrgsbase R:y
0f ae f3 /4 : ptwrite m:y
0f ae f3 r /5 w0 : incsspd R:d
0f ae f3 r /5 w1 : incsspq R:q
0f ae f3 m /6 : clrssbsy M:/d
0f 1e f3 r /1 w0 : rdsspd R:d
0f 1e f3 r /1 w1 : rdsspq R:q
0f 1e f3 @fa : endbr64
0f 1e f3 @fb : endbr32
0f 01 f3 m /5 : rstorssp M:/d
0f 01 f3 @ea : saveprevssp
0f 01 f3 @e8 : setssbsy
38 f6 np m w0 : wrssd M:d, r:d
38 f6 np m w1 : wrssq M:q, r:q
38 f5 66 m w0 : wrussd M:d, r:d
38 f5 66 m w1 : wrussq M:q, r:q
0f af : imul r:v, m:v
0f b0 : cmpxchg m:b, r:b ; lock
0f b1 : cmpxchg m:v, r:v ; lock
0f b2 m : lss r:v, M:/p
0f b3 : btr m:v, r:v ; lock
0f b4 m : lfs r:v, M:/p
0f b5 m : lgs r:v, M:/p
0f b6 : movzx r:v, m:b
0f b7 : movzx r:v, m:w
0f b8 f3|6f3 : popcnt r:v, m:v
0f b9 : ud1
0f ba /4 : bt m:v, i:b
0f ba /5 : bts m:v, i:b ; lock
0f ba /6 : btr m:v, i:b ; lock
0f ba /7 : btc m:v, i:b ; lock
0f bb : btc m:v, r:v ; lock
0f bc np|66 : bsf r:v, m:v
0f bc f3|6f3 : tzcnt r:v, m:v
0f bd np|66 : bsr r:v, m:v
0f bd f3|6f3 : lzcnt r:v, m:v
0f be : movsx r:v, m:b
0f bf : movsx r:v, m:w
# ------------------------------------------------------------------ 0F C0-CF
0f c0 : xadd m:b, r:b ; lock
0f c1 : xadd m:v, r:v ; lock
0f c2 np : cmpps r:x, m:x, i:b ; cmp8
0f c2 66 : cmppd r:x, m:x, i:b ; cmp8
0f c2 f3 : cmpss r:x, m:x/d, i:b ; cmp8
0f c2 f2 : cmpsd r:x, m:x/q, i:b ; cmp8
0f c3 np m : movnti M:y, r:y
0f c4 np : pinsrw r:mm, m:d/w, i:b
0f c4 66 : pinsrw r:x, m:d/w, i:b
0f c5 np r : pextrw r:d, R:mm, i:b
0f c5 66 r : pextrw r:d, R:x, i:b
0f c6 np : shufps r:x, m:x, i:b
0f c6 66 : shufpd r:x, m:x, i:b
0f c7 m /1 o16|o32 : cmpxchg8b M:/q ; lock
0f c7 m /1 o64 : cmpxchg16b M:/x ; lock
0f c7 m /3 np|66|f3|f2 w0 : xrstors M:/p
0f c7 m /3 np|66|f3|f2 w1 : xrstors64 M:/p
0f c7 m /4 np|66|f3|f2 w0 : xsavec M:/p
0f c7 m /4 np|66|f3|f2 w1 : xsavec64 M:/p
0f c7 m /5 np|66|f3|f2 w0 : xsaves M:/p
0f c7 m /5 np|66|f3|f2 w1 : xsaves64 M:/p
0f c7 np m /6 : vmptrld M:/q
0f c7 np m /7 : vmptrst M:/q
0f c7 66 m /6 : vmclear M:/q
0f c7 f3 m /6 : vmxon M:/q
0f c7 np|66 r /6 : rdrand R:v
0f c7 np|66 r /7 : rdseed R:v
0f c7 f3 r /7 : rdpid R:n
0f c8-cf : bswap o:v
# ------------------------------------------------------------------ 0F D0-FF
0f d0 66 : addsubpd r:x, m:x
0f d0 f2 : addsubps r:x, m:x
0f d1 np : psrlw r:mm, m:mm
0f d1 66 : psrlw r:x, m:x
0f d2 np : psrld r:mm, m:mm
0f d2 66 : psrld r:x, m:x
0f d3 np : psrlq r:mm, m:mm
0f d3 66 : psrlq r:x, m:x
0f d4 np : paddq r:mm, m:mm
0f d4 66 : paddq r:x, m:x
0f d5 np : pmullw r:mm, m:mm
0f d5 66 : pmullw r:x, m:x
0f d6 66 : movq m:x/q, r:x
0f d6 f3 r : movq2dq r:x, R:mm
0f d6 f2 r : movdq2q r:mm, R:x
0f d7 np r : pmovmskb r:d, R:mm
0f d7 66 r : pmovmskb r:d, R:x
0f d8 np : psubusb r:mm, m:mm
0f d8 66 : psubusb r:x, m:x
0f d9 np : psubusw r:mm, m:mm
0f d9 66 : psubusw r:x, m:x
0f da np : pminub r:mm, m:mm
0f da 66 : pminub r:x, m:x
0f db np : pand r:mm, m:mm
0f db 66 : pand r:x, m:x
0f dc np : paddusb r:mm, m:mm
0f dc 66 : paddusb r:x, m:x
0f dd np : paddusw r:mm, m:mm
0f dd 66 : paddusw r:x, m:x
0f de np : pmaxub r:mm, m:mm
0f de 66 : pmaxub r:x, m:x
0f df np : pandn r:mm, m:mm
0f df 66 : pandn r:x, m:x
0f e0 np : pavgb r:mm, m:mm
0f e0 66 : pavgb r:x, m:x
0f e1 np : psraw r:mm, m:mm
0f e1 66 : psraw r:x, m:x
0f e2 np : psrad r:mm, m:mm
0f e2 66 : psrad r:x, m:x
0f e3 np : pavgw r:mm, m:mm
0f e3 66 : pavgw r:x, m:x
0f e4 np : pmulhuw r:mm, m:mm
0f e4 66 : pmulhuw r:x, m:x
0f e5 np : pmulhw r:mm, m:mm
0f e5 66 : pmulhw r:x, m:x
0f e6 66 : cvttpd2dq r:x, m:x
0f e6 f3 : cvtdq2pd r:x, m:x/q
0f e6 f2 : cvtpd2dq r:x, m:x
0f e7 np m : movntq M:/q, r:mm
0f e7 66 m : movntdq M:/x, r:x
0f e8 np : psubsb r:mm, m:mm
0f e8 66 : psubsb r:x, m:x
0f e9 np : psubsw r:mm, m:mm
0f e9 66 : psubsw r:x, m:x
0f ea np : pminsw r:mm, m:mm
0f ea 66 : pminsw r:x, m:x
0f eb np : por r:mm, m:mm
0f eb 66 : por r:x, m:x
0f ec np : paddsb r:mm, m:mm
0f ec 66 : paddsb r:x, m:x
0f ed np : paddsw r:mm, m:mm
0f ed 66 : paddsw r:x, m:x
0f ee np : pmaxsw r:mm, m:mm
0f ee 66 : pmaxsw r:x, m:x
0f ef np : pxor r:mm, m:mm
0f ef 66 : pxor r:x, m:x
0f f0 f2 m : lddqu r:x, M:/x
0f f1 np : psllw r:mm, m:mm
0f f1 66 : psllw r:x, m:x
0f f2 np : pslld r:mm, m:mm
0f f2 66 : pslld r:x, m:x
0f f3 np : psllq r:mm, m:mm
0f f3 66 : psllq r:x, m:x
0f f4 np : pmuludq r:mm, m:mm
0f f4 66 : pmuludq r:x, m:x
0f f5 np : pmaddwd r:mm, m:mm
0f f5 66 : pmaddwd r:x, m:x
0f f6 np : psadbw r:mm, m:mm
0f f6 66 : psadbw r:x, m:x
0f f7 np r : maskmovq r:mm, R:mm
0f f7 66 r : maskmovdqu r:x, R:x
0f f8 np : psubb r:mm, m:mm
0f f8 66 : psubb r:x, m:x
0f f9 np : psubw r:mm, m:mm
0f f9 66 : psubw r:x, m:x
0f fa np : psubd r:mm, m:mm
0f fa 66 : psubd r:x, m:x
0f fb np : psubq r:mm, m:mm
0f fb 66 : psubq r:x, m:x
0f fc np : paddb r:mm, m:mm
0f fc 66 : paddb r:x, m:x
0f fd np : paddw r:mm, m:mm
0f fd 66 : paddw r:x, m:x
0f fe np : paddd r:mm, m:mm
0f fe 66 : paddd r:x, m:x
0f ff : ud0
# ------------------------------------------------------------------ 0F 38
38 00 np : pshufb r:mm, m:mm
38 00 66 : pshufb r:x, m:x
38 01 np : phaddw r:mm, m:mm
38 01 66 : phaddw r:x, m:x
38 02 np : phaddd r:mm, m:mm
38 02 66 : phaddd r:x, m:x
38 03 np : phaddsw r:mm, m:mm
38 03 66 : phaddsw r:x, m:x
38 04 np : pmaddubsw r:mm, m:mm
38 04 66 : pmaddubsw r:x, m:x
38 05 np : phsubw r:mm, m:mm
38 05 66 : phsubw r:x, m:x
38 06 np : phsubd r:mm, m:mm
38 06 66 : phsubd r:x, m:x
38 07 np : phsubsw r:mm, m:mm
38 07 66 : phsubsw r:x, m:x
38 08 np : psignb r:mm, m:mm
38 08 66 : psignb r:x, m:x
38 09 np : psignw r:mm, m:mm
38 09 66 : psignw r:x, m:x
38 0a np : psignd r:mm, m:mm
38 0a 66 : psignd r:x, m:x
38 0b np : pmulhrsw r:mm, m:mm
38 0b 66 : pmulhrsw r:x, m:x
38 10 66 : pblendvb r:x, m:x, xmm0
38 14 66 : blendvps r:x, m:x, xmm0
38 15 66 : blendvpd r:x, m:x, xmm0
38 17 66 : ptest r:x, m:x
38 1c np : pabsb r:mm, m:mm
38 1c 66 : pabsb r:x, m:x
38 1d np : pabsw r:mm, m:mm
38 1d 66 : pabsw r:x, m:x
38 1e np : pabsd r:mm, m:mm
38 1e 66 : pabsd r:x, m:x
38 20 66 : pmovsxbw r:x, m:x/q
38 21 66 : pmovsxbd r:x, m:x/d
38 22 66 : pmovsxbq r:x, m:x/w
38 23 66 : pmovsxwd r:x, m:x/q
38 24 66 : pmovsxwq r:x, m:x/d
38 25 66 : pmovsxdq r:x, m:x/q
38 28 66 : pmuldq r:x, m:x
38 29 66 : pcmpeqq r:x, m:x
38 2a 66 m : movntdqa r:x, M:/x
38 2b 66 : packusdw r:x, m:x
38 30 66 : pmovzxbw r:x, m:x/q
38 31 66 : pmovzxbd r:x, m:x/d
38 32 66 : pmovzxbq r:x, m:x/w
38 33 66 : pmovzxwd r:x, m:x/q
38 34 66 : pmovzxwq r:x, m:x/d
38 35 66 : pmovzxdq r:x, m:x/q
38 37 66 : pcmpgtq r:x, m:x
38 38 66 : pminsb r:x, m:x
38 39 66 : pminsd r:x, m:x
38 3a 66 : pminuw r:x, m:x
38 3b 66 : pminud r:x, m:x
38 3c 66 : pmaxsb r:x, m:x
38 3d 66 : pmaxsd r:x, m:x
38 3e 66 : pmaxuw r:x, m:x
38 3f 66 : pmaxud r:x, m:x
38 40 66 : pmulld r:x, m:x
38 41 66 : phminposuw r:x, m:x
38 80 66 m : invept r:n, M:/x
38 81 66 m : invvpid r:n, M:/x
38 82 66 m : invpcid r:n, M:/x
38 c8 : sha1nexte r:x, m:x
38 c9 : sha1msg1 r:x, m:x
38 ca : sha1msg2 r:x, m:x
38 cb : sha256rnds2 r:x, m:x, xmm0
38 cc : sha256msg1 r:x, m:x
38 cd : sha256msg2 r:x, m:x
38 cf 66 : gf2p8mulb r:x, m:x
38 db 66 : aesimc r:x, m:x
38 dc 66 : aesenc r:x, m:x
38 dd 66 : aesenclast r:x, m:x
38 de 66 : aesdec r:x, m:x
38 df 66 : aesdeclast r:x, m:x
38 f0 np|66 m : movbe r:v, M:v
38 f1 np|66 m : movbe M:v, r:v
38 f0 f2 : crc32 r:y, m:b
38 f1 f2|6f2 : crc32 r:y, m:v
38 f8 66 m : movdir64b r:A, M:/zmm
38 f9 m : movdiri M:y, r:y
38 f6 66 : adcx r:y, m:y
38 f6 f3 : adox r:y, m:y
# ------------------------------------------------------------------ 0F 3A
3a 0f np : palignr r:mm, m:mm, i:b
3a 0f 66 : palignr r:x, m:x, i:b
3a 08 66 : roundps r:x, m:x, i:b
3a 09 66 : roundpd r:x, m:x, i:b
3a 0a 66 : roundss r:x, m:x/d, i:b
3a 0b 66 : roundsd r:x, m:x/q, i:b
3a 0c 66 : blendps r:x, m:x, i:b
3a 0d 66 : blendpd r:x, m:x, i:b
3a 0e 66 : pblendw r:x, m:x, i:b
3a 14 66 : pextrb m:d/b, r:x, i:b
3a 15 66 : pextrw m:d/w, r:x, i:b
3a 16 66 w0 : pextrd m:d, r:x, i:b
3a 16 66 w1 : pextrq m:q, r:x, i:b
3a 17 66 : extractps m:d, r:x, i:b
3a 20 66 : pinsrb r:x, m:d/b, i:b
3a 21 66 : insertps r:x, m:x/d, i:b
3a 22 66 w0 : pinsrd r:x, m:d, i:b
3a 22 66 w1 : pinsrq r:x, m:q, i:b
3a 40 66 : dpps r:x, m:x, i:b
3a 41 66 : dppd r:x, m:x, i:b
3a 42 66 : mpsadbw r:x, m:x, i:b
3a 44 66 : pclmulqdq r:x, m:x, i:b
3a 60 66 : pcmpestrm r:x, m:x, i:b
3a 61 66 : pcmpestri r:x, m:x, i:b
3a 62 66 : pcmpistrm r:x, m:x, i:b
3a 63 66 : pcmpistri r:x, m:x, i:b
3a cc : sha1rnds4 r:x, m:x, i:b
3a ce 66 : gf2p8affineqb r:x, m:x, i:b
3a cf 66 : gf2p8affineinvqb r:x, m:x, i:b
3a df 66 : aeskeygenassist r:x, m:x, i:b
# ------------------------------------------------------------------ 3DNow! (suffix byte)
3dn 0c : pi2fw
3dn 0d : pi2fd
3dn 1c : pf2iw
3dn 1d : pf2id
3dn 8a : pfnacc
3dn 8e : pfpnacc
3dn 90 : pfcmpge
3dn 94 : pfmin
3dn 96 : pfrcp
3dn 97 : pfrsqrt
3dn 9a : pfsub
3dn 9e : pfadd
3dn a0 : pfcmpgt
3dn a4 : pfmax
3dn a6 : pfrcpit1
3dn a7 : pfrsqit1
3dn aa : pfsubr
3dn ae : pfacc
3dn b0 : pfcmpeq
3dn b4 : pfmul
3dn b6 : pfrcpit2
3dn b7 : pmulhrw
3dn bb : pswapd
3dn bf : pavgusb
"#;
