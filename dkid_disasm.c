/*
 * dkid_disasm.c - minimal x86/x64 decoder + disassembly view update
 *
 * Decodes common instructions.  Unknown encodings show raw hex bytes.
 * For full capstone support:  #define USE_CAPSTONE and link -lcapstone.
 */
#include "dkid.h"

/* -- operand-size helpers ------------------------------------------- */
typedef struct {
    const BYTE *p;      /* current read pointer */
    const BYTE *end;    /* end of safe read window */
    bool  rex_w;        /* REX.W set? */
    bool  rex_r;
    bool  rex_x;
    bool  rex_b;
    bool  prefix_66;    /* operand-size override */
    bool  prefix_67;    /* address-size override */
    bool  prefix_f2;
    bool  prefix_f3;
    int   seg;          /* 0=none */
} DecState;

static inline BYTE  rd8 (DecState *s){ return (s->p<s->end)?*s->p++:0; }
static inline WORD  rd16(DecState *s){ WORD v=0; if(s->p+1<s->end){v=*(WORD*)s->p;} s->p+=2; return v; }
static inline DWORD rd32(DecState *s){ DWORD v=0; if(s->p+3<s->end){v=*(DWORD*)s->p;} s->p+=4; return v; }
static inline UINT64 rd64(DecState *s){ UINT64 v=0; if(s->p+7<s->end){v=*(UINT64*)s->p;} s->p+=8; return v; }

/* -- register names ------------------------------------------------- */
static const char *REG8[]  = {"al","cl","dl","bl","ah","ch","dh","bh",
                               "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
static const char *REG8R[] = {"al","cl","dl","bl","spl","bpl","sil","dil",
                               "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
static const char *REG16[] = {"ax","cx","dx","bx","sp","bp","si","di",
                               "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
static const char *REG32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                               "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
static const char *REG64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                               "r8","r9","r10","r11","r12","r13","r14","r15"};

static const char *r64(int n, bool rex_b) { return REG64[(n&7)|(rex_b?8:0)]; }
static const char *r32(int n, bool rex_b) { return REG32[(n&7)|(rex_b?8:0)]; }
static const char *r8r(int n, bool rex)   { return rex?REG8R[n&7]:REG8[n&7]; }

/* -- ModRM decoder -> operand string ------------------------------- */
static void decode_modrm(DecState *s, BYTE modrm, bool w64, bool w32,
                          char *out, int outsz)
{
    int mod = (modrm>>6)&3;
    int rm  = (modrm   )&7;
    int ext_rm = rm | (s->rex_b ? 8 : 0);

    if (mod == 3) {
        /* register direct */
        if      (w64) snprintf(out, outsz, "%s", REG64[ext_rm]);
        else if (w32) snprintf(out, outsz, "%s", REG32[ext_rm]);
        else          snprintf(out, outsz, "%s", r8r(ext_rm, s->rex_w|s->rex_r|s->rex_b|s->rex_x));
        return;
    }

    /* memory */
    const char *sz = w64 ? "qword" : w32 ? "dword" : "word";
    char base_s[32] = "";
    bool need_disp32 = false;
    bool has_sib = false;

    if (rm == 4) {
        /* SIB byte */
        has_sib = true;
        BYTE sib  = rd8(s);
        int ss    = (sib>>6)&3;
        int idx   = ((sib>>3)&7) | (s->rex_x ? 8 : 0);
        int base  = (sib&7)    | (s->rex_b ? 8 : 0);
        char idx_s[24] = "", base_n[24] = "";
        if (idx != 4) snprintf(idx_s, 24, "+%s*%d", REG64[idx], 1<<ss);
        if ((base&7)==5 && mod==0) { need_disp32=true; snprintf(base_n,24,""); }
        else snprintf(base_n,24,"%s",REG64[base]);
        snprintf(base_s, 32, "[%s%s", base_n, idx_s);
    } else if (rm == 5 && mod == 0) {
        /* RIP-relative */
        DWORD d32 = rd32(s);
        snprintf(out, outsz, "%s ptr [rip+0x%X]", sz, d32);
        return;
    } else {
        snprintf(base_s, 32, "[%s", REG64[ext_rm]);
    }

    char disp_s[32] = "";
    if (mod == 1) {
        INT8 d8 = (INT8)rd8(s);
        if (d8<0) snprintf(disp_s,32,"-0x%X",(unsigned)(-d8));
        else if (d8>0) snprintf(disp_s,32,"+0x%X",(unsigned)d8);
    } else if (mod == 2 || need_disp32) {
        INT32 d32 = (INT32)rd32(s);
        if (d32<0) snprintf(disp_s,32,"-0x%X",(unsigned)(-d32));
        else if (d32>0) snprintf(disp_s,32,"+0x%X",(unsigned)d32);
    }
    snprintf(out, outsz, "%s ptr %s%s]", sz, base_s, disp_s);
}

/* -- reg field from ModRM ------------------------------------------ */
static const char *modrm_reg64(BYTE modrm, bool rex_r) {
    return REG64[((modrm>>3)&7)|(rex_r?8:0)];
}
static const char *modrm_reg32(BYTE modrm, bool rex_r) {
    return REG32[((modrm>>3)&7)|(rex_r?8:0)];
}

/* =============== main decode function ============================== */
int DisasmBuffer(const BYTE *code, int code_len, UINT64 base_addr,
                 DisasmLine *out, int max_lines)
{
    const BYTE *p   = code;
    const BYTE *end = code + code_len;
    int n = 0;

    while (p < end && n < max_lines)
    {
        DisasmLine *ln = &out[n];
        memset(ln, 0, sizeof(*ln));
        ln->addr       = base_addr + (UINT64)(p - code);
        ln->addr_color = IDA_ADDR;
        ln->mnem_color = IDA_MNEM;
        ln->op_color   = IDA_REG;

        const BYTE *insn_start = p;

        DecState s = {0};
        s.end = end;

        /* -- prefix scan ------------------------------------------- */
        bool done_prefix = false;
        while (!done_prefix && p < end) {
            BYTE b = *p;
            switch (b) {
            case 0x26: case 0x2E: case 0x36: case 0x3E:
            case 0x64: case 0x65: s.seg = b; p++; break;
            case 0x66: s.prefix_66 = true; p++; break;
            case 0x67: s.prefix_67 = true; p++; break;
            case 0xF0: p++; break; /* LOCK */
            case 0xF2: s.prefix_f2 = true; p++; break;
            case 0xF3: s.prefix_f3 = true; p++; break;
            default:
                if (b >= 0x40 && b <= 0x4F) { /* REX */
                    s.rex_w = (b>>3)&1; s.rex_r = (b>>2)&1;
                    s.rex_x = (b>>1)&1; s.rex_b = (b>>0)&1;
                    p++;
                } else done_prefix = true;
                break;
            }
        }
        if (p >= end) break;
        s.p = p + 1; /* point past opcode byte we're about to read */

        BYTE op = *p++;
        bool w64 = s.rex_w;
        bool w32 = !s.prefix_66 && !s.rex_w;

        /* -- decode ------------------------------------------------ */
        if (op == 0x0F) {
            /* 2-byte opcodes */
            if (p >= end) { strncpy(ln->mnem,"???",sizeof(ln->mnem)); goto finish; }
            BYTE op2 = *p++;
            s.p = p;
            char rm_s[64], reg_s[32];

            if (op2 >= 0x80 && op2 <= 0x8F) {
                /* Jcc rel32 */
                static const char *jcc[] = {"jo","jno","jb","jnb","jz","jnz","jbe","ja",
                                             "js","jns","jp","jnp","jl","jge","jle","jg"};
                INT32 rel = (INT32)rd32(&s);
                UINT64 tgt = ln->addr + (UINT64)(s.p - insn_start) + (INT64)rel;
                snprintf(ln->mnem,sizeof(ln->mnem),"%s",jcc[op2-0x80]);
                snprintf(ln->operands,sizeof(ln->operands),"0x%llX",(unsigned long long)tgt);
                ln->is_jmp = true; ln->mnem_color = IDA_YELLOW;
            } else if (op2 == 0xB6 || op2 == 0xBE) {
                BYTE modrm = rd8(&s);
                decode_modrm(&s, modrm, false, false, rm_s, 64);
                snprintf(ln->mnem,sizeof(ln->mnem), op2==0xB6?"movzx":"movsx");
                snprintf(ln->operands,sizeof(ln->operands),"%s, %s",
                         w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r), rm_s);
            } else if (op2 == 0xAF) {
                BYTE modrm = rd8(&s);
                decode_modrm(&s, modrm, w64, w32, rm_s, 64);
                snprintf(ln->mnem,sizeof(ln->mnem),"imul");
                snprintf(ln->operands,sizeof(ln->operands),"%s, %s",
                         w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r),rm_s);
            } else {
                /* unknown 2-byte */
                snprintf(ln->mnem,sizeof(ln->mnem),"0F %02X",op2);
            }
            p = s.p;
        }
        /* -- 1-byte opcodes --------------------------------------- */
        else if (op == 0x90) {
            if (s.prefix_f3) strncpy(ln->mnem,"pause",sizeof(ln->mnem));
            else             strncpy(ln->mnem,"nop",  sizeof(ln->mnem));
        }
        /* PUSH r64 */
        else if (op >= 0x50 && op <= 0x57) {
            strncpy(ln->mnem,"push",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s",r64(op-0x50,s.rex_b));
        }
        /* POP r64 */
        else if (op >= 0x58 && op <= 0x5F) {
            strncpy(ln->mnem,"pop",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s",r64(op-0x58,s.rex_b));
        }
        /* RET */
        else if (op == 0xC3) {
            strncpy(ln->mnem,"ret",sizeof(ln->mnem)); ln->is_ret=true;
            ln->mnem_color = IDA_RED;
        }
        else if (op == 0xC2) {
            WORD imm = (WORD)rd16(&s); p=s.p;
            strncpy(ln->mnem,"ret",sizeof(ln->mnem)); ln->is_ret=true;
            snprintf(ln->operands,sizeof(ln->operands),"0x%X",imm);
            ln->mnem_color = IDA_RED;
        }
        /* CALL rel32 */
        else if (op == 0xE8) {
            INT32 rel = (INT32)rd32(&s); p=s.p;
            UINT64 tgt = ln->addr + (UINT64)(p - insn_start) + (INT64)rel;
            strncpy(ln->mnem,"call",sizeof(ln->mnem)); ln->is_call=true;
            snprintf(ln->operands,sizeof(ln->operands),"0x%llX",(unsigned long long)tgt);
            ln->mnem_color = IDA_GREEN;
        }
        /* JMP rel32 */
        else if (op == 0xE9) {
            INT32 rel = (INT32)rd32(&s); p=s.p;
            UINT64 tgt = ln->addr + (UINT64)(p - insn_start) + (INT64)rel;
            strncpy(ln->mnem,"jmp",sizeof(ln->mnem)); ln->is_jmp=true;
            snprintf(ln->operands,sizeof(ln->operands),"0x%llX",(unsigned long long)tgt);
            ln->mnem_color = IDA_YELLOW;
        }
        /* JMP rel8 */
        else if (op == 0xEB) {
            INT8 rel = (INT8)rd8(&s); p=s.p;
            UINT64 tgt = ln->addr + (UINT64)(p - insn_start) + (INT64)rel;
            strncpy(ln->mnem,"jmp",sizeof(ln->mnem)); ln->is_jmp=true;
            snprintf(ln->operands,sizeof(ln->operands),"0x%llX",(unsigned long long)tgt);
            ln->mnem_color = IDA_YELLOW;
        }
        /* Jcc rel8 */
        else if (op >= 0x70 && op <= 0x7F) {
            static const char *jcc[] = {"jo","jno","jb","jnb","jz","jnz","jbe","ja",
                                         "js","jns","jp","jnp","jl","jge","jle","jg"};
            INT8 rel = (INT8)rd8(&s); p=s.p;
            UINT64 tgt = ln->addr + (UINT64)(p - insn_start) + (INT64)rel;
            snprintf(ln->mnem,sizeof(ln->mnem),"%s",jcc[op-0x70]);
            snprintf(ln->operands,sizeof(ln->operands),"0x%llX",(unsigned long long)tgt);
            ln->is_jmp=true; ln->mnem_color=IDA_YELLOW;
        }
        /* MOV r/m, r */
        else if (op == 0x88 || op == 0x89) {
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s, modrm, w64, w32, rm_s, 64);
            p = s.p;
            strncpy(ln->mnem,"mov",sizeof(ln->mnem));
            if (op == 0x88)
                snprintf(ln->operands,sizeof(ln->operands),"%s, %s",rm_s,r8r((modrm>>3)&7,true));
            else
                snprintf(ln->operands,sizeof(ln->operands),"%s, %s",rm_s,
                         w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r));
        }
        /* MOV r, r/m */
        else if (op == 0x8A || op == 0x8B) {
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s, modrm, w64, w32, rm_s, 64);
            p = s.p;
            strncpy(ln->mnem,"mov",sizeof(ln->mnem));
            if (op == 0x8A)
                snprintf(ln->operands,sizeof(ln->operands),"%s, %s",r8r((modrm>>3)&7,true),rm_s);
            else
                snprintf(ln->operands,sizeof(ln->operands),"%s, %s",
                         w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r), rm_s);
        }
        /* MOV r imm */
        else if ((op >= 0xB0 && op <= 0xB7)) {
            BYTE imm = rd8(&s); p=s.p;
            strncpy(ln->mnem,"mov",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%02X",r8r(op-0xB0,false),imm);
            ln->op_color=IDA_IMM;
        }
        else if ((op >= 0xB8 && op <= 0xBF)) {
            int reg = (op-0xB8)|(s.rex_b?8:0);
            strncpy(ln->mnem,"mov",sizeof(ln->mnem));
            if (s.rex_w) {
                UINT64 imm = rd64(&s); p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%llX",REG64[reg],(unsigned long long)imm);
            } else {
                DWORD imm = rd32(&s); p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%X",REG32[reg],imm);
            }
            ln->op_color=IDA_IMM;
        }
        /* MOV r/m, imm */
        else if (op == 0xC6 || op == 0xC7) {
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s, modrm, w64, w32, rm_s, 64);
            strncpy(ln->mnem,"mov",sizeof(ln->mnem));
            if (op==0xC6) { BYTE imm=rd8(&s); p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%02X",rm_s,imm); }
            else { DWORD imm=rd32(&s); p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%X",rm_s,imm); }
            ln->op_color=IDA_IMM;
        }
        /* LEA */
        else if (op == 0x8D) {
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s, modrm, w64, w32, rm_s, 64);
            p=s.p;
            strncpy(ln->mnem,"lea",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s, %s",
                     w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r), rm_s);
        }
        /* ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m,r */
        else if (op >= 0x00 && op <= 0x3B && (op&7)<=3) {
            static const char *alu[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64); p=s.p;
            snprintf(ln->mnem,sizeof(ln->mnem),"%s",alu[(op>>3)&7]);
            snprintf(ln->operands,sizeof(ln->operands),"%s, %s",rm_s,
                     w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r));
        }
        /* ADD/OR/... r/m,imm (0x80,0x81,0x83) */
        else if (op == 0x80 || op == 0x81 || op == 0x83) {
            static const char *alu[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64);
            int reg = (modrm>>3)&7;
            snprintf(ln->mnem,sizeof(ln->mnem),"%s",alu[reg]);
            if (op==0x80) { BYTE imm=rd8(&s); p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%02X",rm_s,imm); }
            else if (op==0x81) { DWORD imm=rd32(&s); p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%X",rm_s,imm); }
            else { INT8 imm=(INT8)rd8(&s); p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%02X",rm_s,(BYTE)imm); }
            ln->op_color=IDA_IMM;
        }
        /* TEST */
        else if (op == 0x85) {
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64); p=s.p;
            strncpy(ln->mnem,"test",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s, %s",rm_s,
                     w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r));
        }
        /* PUSH imm8/32 */
        else if (op == 0x6A) {
            INT8 imm=(INT8)rd8(&s); p=s.p;
            strncpy(ln->mnem,"push",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"0x%02X",(BYTE)imm);
            ln->op_color=IDA_IMM;
        }
        else if (op == 0x68) {
            DWORD imm=rd32(&s); p=s.p;
            strncpy(ln->mnem,"push",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"0x%X",imm);
            ln->op_color=IDA_IMM;
        }
        /* XCHG */
        else if (op >= 0x91 && op <= 0x97) {
            strncpy(ln->mnem,"xchg",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"rax, %s",r64(op-0x90,s.rex_b));
        }
        /* INC/DEC r32 (legacy) */
        else if (op >= 0x40 && op <= 0x47) {
            strncpy(ln->mnem,"inc",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s",r32(op-0x40,false));
        }
        else if (op >= 0x48 && op <= 0x4F) {
            strncpy(ln->mnem,"dec",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s",r32(op-0x48,false));
        }
        /* FF group: INC/DEC/CALL/JMP/PUSH */
        else if (op == 0xFF) {
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64); p=s.p;
            int reg=(modrm>>3)&7;
            static const char *g_ff[]={"inc","dec","call","call far","jmp","jmp far","push","???"};
            snprintf(ln->mnem,sizeof(ln->mnem),"%s",g_ff[reg]);
            snprintf(ln->operands,sizeof(ln->operands),"%s",rm_s);
            if(reg==2){ln->is_call=true;ln->mnem_color=IDA_GREEN;}
            else if(reg==4){ln->is_jmp=true;ln->mnem_color=IDA_YELLOW;}
        }
        /* CMP r/m */
        else if (op == 0x3B) {
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64); p=s.p;
            strncpy(ln->mnem,"cmp",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"%s, %s",
                     w64?modrm_reg64(modrm,s.rex_r):modrm_reg32(modrm,s.rex_r),rm_s);
        }
        /* INT */
        else if (op == 0xCC) { strncpy(ln->mnem,"int3",sizeof(ln->mnem)); ln->mnem_color=IDA_RED; }
        else if (op == 0xCD) { BYTE imm=rd8(&s);p=s.p;
            strncpy(ln->mnem,"int",sizeof(ln->mnem));
            snprintf(ln->operands,sizeof(ln->operands),"0x%02X",imm); }
        /* HLT/SYSCALL */
        else if (op == 0xF4) { strncpy(ln->mnem,"hlt",sizeof(ln->mnem)); }
        else if (op == 0x0F && p<end && *p==0x05) { p++; strncpy(ln->mnem,"syscall",sizeof(ln->mnem)); }
        /* LEAVE */
        else if (op == 0xC9) { strncpy(ln->mnem,"leave",sizeof(ln->mnem)); }
        /* CBW/CWDE/CDQE */
        else if (op == 0x98) { strncpy(ln->mnem,s.rex_w?"cdqe":"cwde",sizeof(ln->mnem)); }
        /* CQO/CDQ */
        else if (op == 0x99) { strncpy(ln->mnem,s.rex_w?"cqo":"cdq",sizeof(ln->mnem)); }
        /* NOT/NEG (F6/F7) */
        else if (op == 0xF6 || op == 0xF7) {
            static const char *g_f7[]={"test","???","not","neg","mul","imul","div","idiv"};
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64);
            int reg=(modrm>>3)&7;
            snprintf(ln->mnem,sizeof(ln->mnem),"%s",g_f7[reg]);
            if(reg==0){DWORD imm=rd32(&s);p=s.p;
                snprintf(ln->operands,sizeof(ln->operands),"%s, 0x%X",rm_s,imm);}
            else { p=s.p; snprintf(ln->operands,sizeof(ln->operands),"%s",rm_s); }
        }
        /* SHL/SHR/SAR (D0-D3) */
        else if (op >= 0xD0 && op <= 0xD3) {
            static const char *sh[]={"rol","ror","rcl","rcr","shl","shr","???","sar"};
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64); p=s.p;
            snprintf(ln->mnem,sizeof(ln->mnem),"%s",sh[(modrm>>3)&7]);
            snprintf(ln->operands,sizeof(ln->operands),"%s, %s",rm_s,
                     (op==0xD2||op==0xD3)?"cl":"1");
        }
        else if (op == 0xC1) {
            static const char *sh[]={"rol","ror","rcl","rcr","shl","shr","???","sar"};
            BYTE modrm = rd8(&s);
            char rm_s[64]; decode_modrm(&s,modrm,w64,w32,rm_s,64);
            BYTE imm=rd8(&s); p=s.p;
            snprintf(ln->mnem,sizeof(ln->mnem),"%s",sh[(modrm>>3)&7]);
            snprintf(ln->operands,sizeof(ln->operands),"%s, %d",rm_s,imm);
            ln->op_color=IDA_IMM;
        }
        /* MOVAPS/MOVDQU/PXOR/AESENC etc (placeholder) */
        else {
            snprintf(ln->mnem,sizeof(ln->mnem),"%02X",op);
            ln->mnem_color=IDA_TEXT2;
        }

finish:
        if (s.p > p) p = s.p;
        /* raw bytes */
        int raw = (int)(p - insn_start);
        if (raw <= 0) { raw = 1; p = insn_start + 1; }
        if (raw > 15) raw = 15;
        ln->raw_len = raw;
        memcpy(ln->raw, insn_start, raw);

        /* default mnem if empty */
        if (!ln->mnem[0]) snprintf(ln->mnem,sizeof(ln->mnem),"%02X",insn_start[0]);
        n++;
    }
    return n;
}

static void DisasmRefreshCore(bool noisy)
{
    if (!g_target || !g_dll_base) {
        if (noisy) Log(IDA_RED, "[!] Attach and select a module first");
        return;
    }

    /* find .text section */
    UINT64 text_va = 0; DWORD text_sz = 0;
    for (int i = 0; i < g_sec_count; i++) {
        if (_stricmp(g_sections[i].name, ".text") == 0) {
            text_va = g_sections[i].va;
            text_sz = g_sections[i].vsize;
            break;
        }
    }

    if (!text_va) {
        /* No .text found: use whole module header area */
        text_va = g_dll_base;
        text_sz = min(g_dll_size, 65536);
    }
    if (text_sz > 512*1024) text_sz = 512*1024;

    BYTE *buf = (BYTE*)malloc(text_sz);
    if (!buf) { if (noisy) Log(IDA_RED,"[!] Out of memory"); return; }
    SIZE_T got = 0;
    if (!ReadProcessMemory(g_target, (LPCVOID)(uintptr_t)text_va, buf, text_sz, &got) || !got) {
        if (noisy) Log(IDA_RED,"[!] ReadProcessMemory failed for .text section");
        free(buf);
        return;
    }

    int prev_sel = 0;
    EnterCriticalSection(&g_disasm_cs);
    prev_sel = g_disasm_sel;
    g_disasm_count = DisasmBuffer(buf, (int)got, text_va, g_disasm, MAX_DISASM_LINES);
    g_disasm_sel   = (prev_sel >= 0 && prev_sel < g_disasm_count) ? prev_sel : 0;
    LeaveCriticalSection(&g_disasm_cs);

    if (noisy) {
        Log(IDA_GREEN, "[*] Disassembled %d instructions from %s .text (0x%llX)",
            g_disasm_count, g_dll_name, (unsigned long long)text_va);
    }
    free(buf);
}

/* =========================================== DisasmRefresh ========== */
/* Reads the .text section of the selected module and disassembles it */
void DisasmRefresh(void)
{
    DisasmRefreshCore(true);
}

void DisasmRefreshLive(void)
{
    DisasmRefreshCore(false);
}
