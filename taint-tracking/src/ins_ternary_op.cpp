#include "ins_ternary_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

void _pmovmskb_r2r_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag = RTAG[src][0];
    for (size_t i = 1; i < 8; i++) {
        tag_combine(src_tag, RTAG[src][i]);
    }

    RTAG[dst][0] = src_tag;

    for (size_t i = 1; i < 8; i++) {
        RTAG[dst][i] = tag_traits<lb_type>::cleared_val;
    }
}

void _pmovmskb_r2r_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag = RTAG[src][0];
    for (size_t i = 1; i < 16; i++) {
        tag_combine(src_tag, RTAG[src][i]);
    }

    for (size_t i = 0; i < 2; i++) {
        RTAG[dst][i] = src_tag;
    }

    for (size_t i = 2; i < 8; i++) {
        RTAG[dst][i] = tag_traits<lb_type>::cleared_val;
    }
}

void _pmovmskb_r2r_opy(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag = RTAG[src][0];
    for (size_t i = 1; i < 32; i++) {
        tag_combine(src_tag, RTAG[src][i]);
    }

    for (size_t i = 0; i < 4; i++) {
        RTAG[dst][i] = src_tag;
    }

    for (size_t i = 4; i < 8; i++) {
        RTAG[dst][i] = tag_traits<lb_type>::cleared_val;
    }
}

void _pminub_r2r_opq(THREADID tid, uint32_t dst, uint8_t *dst_val, uint32_t src, uint8_t *src_val) {
    for (size_t i = 0; i < 8; i++) {
        if (src_val[i] <= dst_val[i]) {
            RTAG[dst][i] = RTAG[src][i];
        }
    }
}

void _pminub_r2r_opx(THREADID tid, uint32_t dst, uint8_t *dst_val, uint32_t src, uint8_t *src_val) {
    for (size_t i = 0; i < 16; i++) {
        if (src_val[i] <= dst_val[i]) {
            RTAG[dst][i] = RTAG[src][i];
        }
    }
}

void _pminub_m2r_opq(THREADID tid, uint32_t dst, uint8_t *dst_val, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    for (size_t i = 0; i < 8; i++) {
        uint8_t src_val = *(uint8_t *)(src + i);
        if (src_val <= dst_val[i]) {
            RTAG[dst][i] = src_tags[i];
        }
    }
}

void _pminub_m2r_opx(THREADID tid, uint32_t dst, uint8_t *dst_val, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    for (size_t i = 0; i < 16; i++) {
        uint8_t src_val = *(uint8_t *)(src + i);
        if (src_val <= dst_val[i]) {
            RTAG[dst][i] = src_tags[i];
        }
    }
}

void _vpminub_r2r_opx(THREADID tid, uint32_t dst, uint8_t *dst_val, uint32_t src1, uint8_t *src1_val, uint32_t src2, uint8_t *src2_val) {
    for (size_t i = 0; i < 16; i++) {
        if (src1_val[i] <= src2_val[i]) {
            RTAG[dst][i] = RTAG[src1][i];
        } else {
            RTAG[dst][i] = RTAG[src2][i];
        }
    }
}

void _vpminub_r2r_opy(THREADID tid, uint32_t dst, uint8_t *dst_val, uint32_t src1, uint8_t *src1_val, uint32_t src2, uint8_t *src2_val) {
    for (size_t i = 0; i < 32; i++) {
        if (src1_val[i] <= src2_val[i]) {
            RTAG[dst][i] = RTAG[src1][i];
        } else {
            RTAG[dst][i] = RTAG[src2][i];
        }
    }
}

void _vpminub_m2r_opx(THREADID tid, uint32_t dst, uint8_t *dst_val, uint32_t src1, uint8_t *src1_val, ADDRINT src2) {
    tag_t src2_tags[] = M128TAG(src2);
    for (size_t i = 0; i < 16; i++) {
        uint8_t src2_val = *(uint8_t *)(src2 + i);
        if (src2_val <= src1_val[i]) {
            RTAG[dst][i] = src2_tags[i];
        } else {
            RTAG[dst][i] = RTAG[src1][i];
        }
    }
}

void _vpminub_m2r_opy(THREADID tid, uint32_t dst, uint8_t *dst_val, uint32_t src1, uint8_t *src1_val, ADDRINT src2) {
    tag_t src2_tags[] = M256TAG(src2);
    for (size_t i = 0; i < 32; i++) {
        uint8_t src2_val = *(uint8_t *)(src2 + i);
        if (src2_val <= src1_val[i]) {
            RTAG[dst][i] = src2_tags[i];
        } else {
            RTAG[dst][i] = RTAG[src1][i];
        }
    }
}

void ins_pmovmskb_op(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_mm(reg_src)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pmovmskb_r2r_opq,
                       IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, REG_INDX(reg_src),
                       IARG_END);
    } else if (REG_is_xmm(reg_src)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pmovmskb_r2r_opx,
                       IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, REG_INDX(reg_src),
                       IARG_END);
    } else if (REG_is_ymm(reg_src)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pmovmskb_r2r_opy,
                       IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, REG_INDX(reg_src),
                       IARG_END);
    } else {
        xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
        LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
    }
}

void ins_pminub_op(INS ins) {
    // 2 operands, byte integers
    REG reg_dst, reg_src;
    if (INS_MemoryOperandCount(ins) == 0) {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pminub_r2r_opq,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_REG_CONST_REFERENCE, reg_src,
                           IARG_END);
        } else if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pminub_r2r_opx,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_REG_CONST_REFERENCE, reg_src,
                           IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pminub_m2r_opq,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pminub_m2r_opx,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    }
}

void ins_vpminub_op(INS ins) {
    // 3 operands, byte integers
    REG reg_dst, reg_src1, reg_src2;
    reg_dst = INS_OperandReg(ins, OP_0);

    if (INS_MemoryOperandCount(ins) == 0) {
        reg_src1 = INS_OperandReg(ins, OP_1);
        reg_src2 = INS_OperandReg(ins, OP_2);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpminub_r2r_opx,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_REG_CONST_REFERENCE, reg_src1,
                           IARG_UINT32, REG_INDX(reg_src2),
                           IARG_REG_CONST_REFERENCE, reg_src2,
                           IARG_END);
        } else if (REG_is_ymm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpminub_r2r_opy,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_REG_CONST_REFERENCE, reg_src1,
                           IARG_UINT32, REG_INDX(reg_src2),
                           IARG_REG_CONST_REFERENCE, reg_src2,
                           IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    } else {
        reg_src1 = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpminub_m2r_opx,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_REG_CONST_REFERENCE, reg_src1,
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpminub_m2r_opy,
                           IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_dst,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_REG_CONST_REFERENCE, reg_src1,
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_ternary_opl(THREADID tid, uint32_t reg_src1, uint32_t reg_src2, uint32_t reg_dst) {
    tag_t src1_tags[] = R32TAG(reg_src1);
    tag_t src2_tags[] = R32TAG(reg_src2);

    for (size_t i = 0; i < 4; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_ternary_opq(THREADID tid, uint32_t reg_src1, uint32_t reg_src2, uint32_t reg_dst) {
    tag_t src1_tags[] = R64TAG(reg_src1);
    tag_t src2_tags[] = R64TAG(reg_src2);

    for (size_t i = 0; i < 8; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_ternary_opx(THREADID tid, uint32_t reg_src1, uint32_t reg_src2, uint32_t reg_dst) {
    tag_t src1_tags[] = R128TAG(reg_src1);
    tag_t src2_tags[] = R128TAG(reg_src2);

    for (size_t i = 0; i < 16; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_ternary_opy(THREADID tid, uint32_t reg_src1, uint32_t reg_src2, uint32_t reg_dst) {
    tag_t src1_tags[] = R256TAG(reg_src1);
    tag_t src2_tags[] = R256TAG(reg_src2);

    for (size_t i = 0; i < 32; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_ternary_opl(THREADID tid, uint32_t reg_dst, uint32_t reg_src1, ADDRINT src2) {
    tag_t src1_tags[] = R32TAG(reg_src1);
    tag_t src2_tags[] = M32TAG(src2);

    for (size_t i = 0; i < 4; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_ternary_opq(THREADID tid, uint32_t reg_dst, uint32_t reg_src1, ADDRINT src2) {
    tag_t src1_tags[] = R64TAG(reg_src1);
    tag_t src2_tags[] = M64TAG(src2);

    for (size_t i = 0; i < 8; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_ternary_opx(THREADID tid, uint32_t reg_dst, uint32_t reg_src1, ADDRINT src2) {
    tag_t src1_tags[] = R128TAG(reg_src1);
    tag_t src2_tags[] = M128TAG(src2);

    for (size_t i = 0; i < 16; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_ternary_opy(THREADID tid, uint32_t reg_dst, uint32_t reg_src1, ADDRINT src2) {
    tag_t src1_tags[] = R256TAG(reg_src1);
    tag_t src2_tags[] = M256TAG(src2);

    for (size_t i = 0; i < 32; i++) {
        RTAG[reg_dst][i] = tag_combine(src1_tags[i], src2_tags[i]);
    }
}
/*
static void PIN_FAST_ANALYSIS_CALL r2m_ternary_opx(THREADID tid, uint32_t reg_src1, uint32_t reg_src2, ADDRINT dst) {
    tag_t src1_tags[] = R128TAG(reg_src1);
    tag_t src2_tags[] = R128TAG(reg_src2);

    tag_t res_tags[16];
    for (size_t i = 0; i < 16; i++) {
        res_tags[i] = tag_combine(src1_tags[i], src2_tags[i]);
        tagmap_setb(dst + i, res_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL r2m_ternary_opy(THREADID tid, uint32_t reg_src1, uint32_t reg_src2, ADDRINT dst) {
    tag_t src1_tags[] = R256TAG(reg_src1);
    tag_t src2_tags[] = R256TAG(reg_src2);

    tag_t res_tags[32];
    for (size_t i = 0; i < 32; i++) {
        res_tags[i] = tag_combine(src1_tags[i], src2_tags[i]);
        tagmap_setb(dst + i, res_tags[i]);
    }
}*/

static void PIN_FAST_ANALYSIS_CALL m2r_ternary_op_imm(THREADID tid, uint32_t reg_dst, uint64_t address, uint32_t byteCount) {
    tag_t *dst_tags = RTAG[reg_dst];
    for (size_t i = 0; i < byteCount; i++)
        dst_tags[i] = MTAG(address + i);
}

static void PIN_FAST_ANALYSIS_CALL r2r_ternary_op_imm(THREADID tid, uint32_t reg_dst, uint32_t reg_src1, uint32_t byteCount) {
    tag_t *src_tags = RTAG[reg_src1];
    tag_t *dst_tags = RTAG[reg_dst];
    for (size_t i = 0; i < byteCount; ++i)
        dst_tags[i] = src_tags[i];
}

void ins_ternary_op(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (INS_OperandIsImmediate(ins, OP_2)) {
        if (INS_OperandIsMemory(ins, OP_1)) {
            if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) m2r_ternary_op_imm,
                            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                            IARG_UINT32, REG_INDX(reg_dst),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, 2,
                            IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) m2r_ternary_op_imm,
                            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                            IARG_UINT32, REG_INDX(reg_dst),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, 4,
                            IARG_END);
            } else if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) m2r_ternary_op_imm,
                            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                            IARG_UINT32, REG_INDX(reg_dst),
                            IARG_MEMORYREAD_EA,
                            IARG_UINT32, 8,
                            IARG_END);
            }
        } else {
            REG reg_src1 = INS_OperandReg(ins, OP_1);
            if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) r2r_ternary_op_imm,
                            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                            IARG_UINT32, REG_INDX(reg_dst),
                            IARG_UINT32, REG_INDX(reg_src1),
                            IARG_UINT32, 2,
                            IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) r2r_ternary_op_imm,
                            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                            IARG_UINT32, REG_INDX(reg_dst),
                            IARG_UINT32, REG_INDX(reg_src1),
                            IARG_UINT32, 4,
                            IARG_END);
            } else if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) r2r_ternary_op_imm,
                            IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                            IARG_UINT32, REG_INDX(reg_dst),
                            IARG_UINT32, REG_INDX(reg_src1),
                            IARG_UINT32, 8,
                            IARG_END);
            }
        }
        
    } else if (INS_OperandIsMemory(ins, OP_2) && INS_OperandIsReg(ins, OP_1)) {
        REG reg_src1 = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_ternary_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else if (REG_is_ymm(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_ternary_opy,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else if (REG_is_gr32(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_ternary_opl,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else if (REG_is_gr64(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_ternary_opq,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    } else {
        REG reg_src1 = INS_OperandReg(ins, OP_1);
        REG reg_src2 = INS_OperandReg(ins, OP_2);
        if (REG_is_xmm(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_ternary_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_UINT32, REG_INDX(reg_src2),
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_END);
        } else if (REG_is_ymm(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_ternary_opy,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_UINT32, REG_INDX(reg_src2),
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_END);
        } else if (REG_is_gr32(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_ternary_opl,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_UINT32, REG_INDX(reg_src2),
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_END);
        } else if (REG_is_gr64(reg_src1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_ternary_opq,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_UINT32, REG_INDX(reg_src2),
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_END);
        }  else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    }
}

void clear_xmm(THREADID tid, UINT32 reg) {
    for (size_t i = 0; i < 16; ++i) {
            RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
        }
}

void clear_ymm(THREADID tid, UINT32 reg) {
    for (size_t i = 0; i < 32; ++i) {
            RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
        }
}    

void ins_clear_ternary_op(INS ins) {
    REG reg = INS_OperandReg(ins, OP_0);

    if (REG_is_xmm(reg)) {   
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(clear_xmm),
            IARG_THREAD_ID,
            IARG_UINT32, REG_INDX(reg),
            IARG_END);
    } else if (REG_is_ymm(reg)) {
        INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(clear_ymm),
            IARG_THREAD_ID,
            IARG_UINT32, REG_INDX(reg),
            IARG_END);
    }     
}



static void PIN_FAST_ANALYSIS_CALL r_sarx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    if (imm > byteCount * 8 - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t src_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = RTAG[reg_src][i];
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Clear all whole bytes
    for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        // Shift the tainted values
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            RTAG[reg_dst][i] = src_tags[i + res.quot];
        }
    } else { // We need to combine the taint
        RTAG[reg_dst][byteCount - res.quot - 1] = src_tags[byteCount - 1];
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            RTAG[reg_dst][i] = tag_combine(src_tags[i + res.quot], src_tags[i + res.quot + 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r_reg_sarx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r_sarx_op(tid, reg_dst, reg_src, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL m_sarx_op(THREADID tid, uint64_t addr, uint32_t reg_dst, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    if (imm > byteCount * 8 - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t src_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Clear all whole bytes
    for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        // Shift the tainted values
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            RTAG[reg_dst][i] = src_tags[i + res.quot];
        }
    } else { // We need to combine the taint
        RTAG[reg_dst][byteCount - res.quot - 1] = src_tags[byteCount - 1];
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            RTAG[reg_dst][i] = tag_combine(src_tags[i + res.quot], src_tags[i + res.quot + 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m_reg_sarx_op(THREADID tid, uint64_t addr, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    m_sarx_op(tid, addr, reg_dst, imm, byteCount);
}

void ins_sarx_op(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_cnt = INS_OperandReg(ins, OP_2);
    if (INS_OperandIsReg(ins, OP_1)) {
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_gr32(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_sarx_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
        } else if (REG_is_gr64(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_sarx_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    } else {
        if (REG_is_gr32(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_sarx_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
        } else if (REG_is_gr64(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_sarx_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_pinsrd_opx(THREADID tid, ADDRINT src, uint32_t dst, uint32_t imm) {
    if (imm > 11)
        return;

    tag_t src_tags[] = M32TAG(src);
    for (size_t i = 0; i < 4; ++i)
    {
        RTAG[dst][imm + i] = src_tags[i];
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_pinsrd_opx(THREADID tid, uint32_t dst, uint32_t src, uint32_t imm) {
    if (imm > 11)
        return;

    tag_t src_tags[] = R32TAG(src);
    for (size_t i = 0; i < 4; ++i)
    {
        RTAG[dst][imm + i] = src_tags[i];
    }
}

void ins_pinsrd_op(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    UINT32 imm = INS_OperandImmediate(ins, OP_2) & 0xFF;
    if (INS_OperandIsMemory(ins, OP_1)) {
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_pinsrd_opx,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYREAD_EA,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    } else {
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_pinsrd_opx,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, imm,
                               IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_vinserti_opy(THREADID tid, uint32_t reg_src1, uint32_t reg_src2, uint32_t reg_dst, uint32_t imm) {
    tag_t src1_tags[] = R256TAG(reg_src1);
    tag_t src2_tags[] = R128TAG(reg_src2);

    if (imm == 0)
    {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = src2_tags[i];
        }
        for (size_t i = 16; i < 32; i++) {
            RTAG[reg_dst][i] = src1_tags[i];
        }
    }
    else 
    {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = src1_tags[i];
        }
        for (size_t i = 16; i < 32; i++) {
            RTAG[reg_dst][i] = src2_tags[i - 16];
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_vinserti_opy(THREADID tid, uint32_t reg_dst, uint32_t reg_src1, ADDRINT src2, uint32_t imm) {
    tag_t src1_tags[] = R256TAG(reg_src1);
    tag_t src2_tags[] = M128TAG(src2);

    if (imm == 0)
    {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = src2_tags[i];
        }
        for (size_t i = 16; i < 32; i++) {
            RTAG[reg_dst][i] = src1_tags[i];
        }
    }
    else 
    {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = src1_tags[i];
        }
        for (size_t i = 16; i < 32; i++) {
            RTAG[reg_dst][i] = src2_tags[i - 16];
        }
    }
}

void ins_vinserti_op(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src1 = INS_OperandReg(ins, OP_1);
    uint32_t imm = INS_OperandImmediate(ins, OP_3) & 1;
    if (INS_OperandIsMemory(ins, OP_2)) {
        if (REG_is_ymm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_vinserti_opy,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, imm,
                           IARG_END);
        } else {
            xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
            LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
        }
    } else {
        REG reg_src2 = INS_OperandReg(ins, OP_2);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_vinserti_opy,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_src1),
                       IARG_UINT32, REG_INDX(reg_src2),
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, imm,
                       IARG_END);
    }
}