#include "ins_binary_op.h"
#include "ins_helper.h"
#include "log.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_ul(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_lu(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opw(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opl(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opq(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opx(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opy(THREADID tid, uint32_t dst,
                                                  uint32_t src) {

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opw(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opl(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opq(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opx(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opy(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_u(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_l(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opw(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opl(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opq(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opx(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opy(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

void ins_binary_op(INS ins) {
  if (INS_OperandIsImmediate(ins, OP_1))
    return;
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_binary_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_binary_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_binary_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_binary_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        R2R_CALL(r2r_binary_opb_l, reg_dst, reg_src);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        R2R_CALL(r2r_binary_opb_u, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))
        R2R_CALL(r2r_binary_opb_lu, reg_dst, reg_src);
      else
        R2R_CALL(r2r_binary_opb_ul, reg_dst, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_binary_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_binary_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_binary_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_binary_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_binary_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_binary_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_binary_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_binary_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_binary_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_binary_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_binary_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_binary_opb_l, reg_src);
    }
  }
}

void ins_padd_op(INS ins) {
    REG reg_dst, reg_src;
    if (INS_MemoryOperandCount(ins) == 0) {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_binary_opx, reg_dst, reg_src);
        } else if (REG_is_ymm(reg_dst)) {
            R2R_CALL(r2r_binary_opy, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            M2R_CALL(m2r_binary_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_binary_opx, reg_dst);
        } else if (REG_is_ymm(reg_dst)) {
            M2R_CALL(m2r_binary_opy, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_shufpd_opx(THREADID tid, uint32_t dst, uint32_t src, uint32_t imm) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    // Depending on the two low bits of imm, we need the tag of x[63:0] or x[127:64]
    // By multiplying with 8, we can directly choose the needed byte taint value
    size_t choice0 = (imm & 0x1) * 8;
    size_t choice1 = ((imm & 0x2) >> 1) * 8;

    for (size_t i = 0; i < 8; ++i)
    {
      RTAG[dst][i] = dst_tags[i + choice0];
      RTAG[dst][i + 8] = src_tags[i + choice1];
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_shufpd_opx(THREADID tid, ADDRINT dst, uint32_t src, uint32_t imm) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    // Depending on the two low bits of imm, we need the tag of x[63:0] or x[127:64]
    // By multiplying with 8, we can directly choose the needed byte taint value
    size_t choice0 = (imm & 0x1) * 8;
    size_t choice1 = ((imm & 0x2) >> 1) * 8;

    for (size_t i = 0; i < 8; ++i)
    {
      RTAG[dst][i] = dst_tags[i + choice0];
      RTAG[dst][i + 8] = src_tags[i + choice1];
    }
}

void ins_shufpd_op(INS ins) {
    REG reg_dst, reg_src;
    UINT32 imm = INS_OperandImmediate(ins, OP_2) & 0x3;
    if (INS_OperandIsMemory(ins, OP_1)) {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_shufpd_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, imm,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shufpd_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_shufps_opx(THREADID tid, uint32_t dst, uint32_t src, uint32_t imm) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t choice0 = imm & 0x3; // imm[1:0]
    size_t choice1 = (imm & 0xc) >> 2; // imm[3:2]
    size_t choice2 = (imm & 0x30) >> 4; // imm[5:4]
    size_t choice3 = (imm & 0xc0) >> 6; // imm[7:6]

    for (size_t i = 0; i < 4; ++i)
    {
        RTAG[dst][i] = dst_tags[i + (choice0 * 4)]; 
        RTAG[dst][i + 4] = dst_tags[i + (choice1 * 4)];
        RTAG[dst][i + 8] = src_tags[i + (choice2 * 4)];
        RTAG[dst][i + 12] = src_tags[i + (choice3 * 4)];
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_shufps_opx(THREADID tid, ADDRINT src, uint32_t dst, uint32_t imm) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t choice0 = imm & 0x3; // imm[1:0]
    size_t choice1 = (imm & 0xc) >> 2; // imm[3:2]
    size_t choice2 = (imm & 0x30) >> 4; // imm[5:4]
    size_t choice3 = (imm & 0xc0) >> 6; // imm[7:6]

    for (size_t i = 0; i < 4; ++i)
    {
        RTAG[dst][i] = dst_tags[i + (choice0 * 4)];
        RTAG[dst][i + 4] = dst_tags[i + (choice1 * 4)];
        RTAG[dst][i + 8] = src_tags[i + (choice2 * 4)];
        RTAG[dst][i + 12] = src_tags[i + (choice3 * 4)];
    }
}

void ins_shufps_op(INS ins) {
    REG reg_dst, reg_src;
    UINT32 imm = INS_OperandImmediate(ins, OP_2) & 0xff;
    if (INS_OperandIsMemory(ins, OP_1)) {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_shufps_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, imm,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shufps_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}
