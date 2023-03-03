#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"

#include "ins_xfer_op.h"
#include "ins_clear_op.h"
#include "ins_helper.h"
#include "log.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 2; i++) {
    RTAG[dst][i] = RTAG[src][i];
    /*
    if (!tag_is_empty(RTAG[src][i]))
      LOGD("[xfer_w] i%ld: src: %d (%d) -> dst: %d (%d)\n", i, src,
           RTAG[src][i], dst, RTAG[dst][i]);
           */
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 4; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = MTAG(src);

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = MTAG(src);

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  tagmap_setb(dst, src_tags[0]);
  tagmap_setb(dst + 1, src_tags[1]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src) {
  tag_t src_tag = MTAG(src);

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i + 8] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_h(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i + 8]);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag = RTAG[DFT_REG_RAX][0];
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < count; i++) {
      tagmap_setb(dst + i, src_tag);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < count; i++) {
      size_t dst_addr = dst - count + 1 + i;
      tagmap_setb(dst_addr, src_tag);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opwn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R16TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 1); i++) {
      tagmap_setb(dst + i, src_tag[i % 2]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 1); i++) {
      size_t dst_addr = dst - (count << 1) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 2]);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opln(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R32TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 2); i++) {
      tagmap_setb(dst + i, src_tag[i % 4]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 2); i++) {
      size_t dst_addr = dst - (count << 2) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 4]);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opqn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R64TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 3); i++) {
      tagmap_setb(dst + i, src_tag[i % 8]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 3); i++) {
      size_t dst_addr = dst - (count << 3) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 8]);
    }
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL rep_predicate(BOOL first_iteration) {
  /* return the flag; typically this is true only once */
  return first_iteration;
}

static void PIN_FAST_ANALYSIS_CALL _lea_opw(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opl(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opq(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

void ins_xfer_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_xfer_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_xfer_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {
        R2R_CALL(r2r_xfer_opb_l, reg_dst, reg_src);
      } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src)) {
        R2R_CALL(r2r_xfer_opb_u, reg_dst, reg_src);
      } else if (REG_is_Lower8(reg_dst)) {
        R2R_CALL(r2r_xfer_opb_lu, reg_dst, reg_src);
      } else {
        R2R_CALL(r2r_xfer_opb_ul, reg_dst, reg_src);
      }
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_xfer_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_xfer_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_xfer_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_xfer_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_xfer_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_xfer_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_xfer_opb_l, reg_src);
    }
  }
}

void ins_xfer_op_predicated(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_P(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_P(r2r_xfer_opl, reg_dst, reg_src);
    } else {
      R2R_CALL_P(r2r_xfer_opw, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_P(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_P(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL_P(m2r_xfer_opw, reg_dst);
    }
  }
}

void ins_push_op(INS ins) {
  REG reg_src;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src);
    } else {
      R2M_CALL(r2m_xfer_opw, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  } else {
    M_CLEAR_N(8); // push always writes 8 bytes
  }
}

void ins_pop_op(INS ins) {
  REG reg_dst;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryOperandSize(ins, OP_0) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  }
}

void ins_stos_ins(INS ins, AFUNPTR fn) {
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_MEMORYWRITE_EA, IARG_REG_VALUE, INS_RepCountRegister(ins),
      IARG_REG_VALUE, INS_OperandReg(ins, OP_4), IARG_END);
}

void ins_stosb(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opbn);
  } else {
    R2M_CALL(r2m_xfer_opb_l, REG_AL);
  }
}

void ins_stosw(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opwn);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_AX);
  }
}

void ins_stosd(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opln);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_EAX);
  }
}

void ins_stosq(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opqn);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_RAX);
  }
}

void ins_movlp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL(r2m_xfer_opq, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq, reg_dst);
  }
}

void ins_movhp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL(r2m_xfer_opq_h, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq_h, reg_dst);
  }
}

void ins_lea(INS ins) {
  REG reg_base = INS_MemoryBaseReg(ins);
  REG reg_indx = INS_MemoryIndexReg(ins);
  REG reg_dst = INS_OperandReg(ins, OP_0);
  if (reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
    ins_clear_op(ins);
  }
  if (reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_base);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_base);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_base);
    }
  }
  if (reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_indx);
    }
  }
  if (reg_base != REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      RR2R_CALL(_lea_opq, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      RR2R_CALL(_lea_opl, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      RR2R_CALL(_lea_opw, reg_dst, reg_base, reg_indx);
    }
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = MTAG(src + (1 - i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = MTAG(src + (3 - i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = MTAG(src + (7 - i));
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tagmap_setb(dst, src_tags[1]);
  tagmap_setb(dst + 1, src_tags[0]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + (3 - i), src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + (7 - i), src_tags[i]);
}

void ins_movbe_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_1)) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq_rev, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl_rev, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw_rev, reg_dst);
    }
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq_rev, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl_rev, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw_rev, reg_src);
    }
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpcklbw_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    for (size_t i = 0; i < 4; i++) {
        RTAG[dst][2*i] = dst_tags[i];
        RTAG[dst][2*i + 1] = src_tags[i];
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpcklbw_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][2*i] = dst_tags[i];
        RTAG[dst][2*i + 1] = src_tags[i];
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpcklbw_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    for (size_t i = 0; i < 4; i++) {
        RTAG[dst][2*i] = dst_tags[i];
        RTAG[dst][2*i + 1] = src_tags[i];
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpcklbw_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][2*i] = dst_tags[i];
        RTAG[dst][2*i + 1] = src_tags[i];
    }
}

void ins_punpcklbw_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            R2R_CALL(r2r_punpcklbw_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpcklbw_opx, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            M2R_CALL(m2r_punpcklbw_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpcklbw_opx, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpcklwd_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 8; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpcklwd_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 16; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpcklwd_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 8; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpcklwd_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 16; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void ins_punpcklwd_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            R2R_CALL(r2r_punpcklwd_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpcklwd_opx, reg_dst, reg_src);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            M2R_CALL(m2r_punpcklwd_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpcklwd_opx, reg_dst);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckldq_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 8; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckldq_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 16; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckldq_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 8; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckldq_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 16; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void ins_punpckldq_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            R2R_CALL(r2r_punpckldq_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpckldq_opx, reg_dst, reg_src);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            M2R_CALL(m2r_punpckldq_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpckldq_opx, reg_dst);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpcklqdq_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 8] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpcklqdq_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 0;
    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 8] = src_tags[j];
        j++;
    }
}

void ins_punpcklqdq_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpcklqdq_opx, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpcklqdq_opx, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckhbw_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    for (size_t i = 0; i < 4; i++) {
        RTAG[dst][2*i] = dst_tags[i + 4];
        RTAG[dst][2*i + 1] = src_tags[i + 4];
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckhbw_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][2*i] = dst_tags[i + 8];
        RTAG[dst][2*i + 1] = src_tags[i + 8];
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckhbw_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    for (size_t i = 0; i < 4; i++) {
        RTAG[dst][2*i] = dst_tags[i + 4];
        RTAG[dst][2*i + 1] = src_tags[i + 4];
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckhbw_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][2*i] = dst_tags[i + 8];
        RTAG[dst][2*i + 1] = src_tags[i + 8];
    }
}

void ins_punpckhbw_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            R2R_CALL(r2r_punpckhbw_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpckhbw_opx, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            M2R_CALL(m2r_punpckhbw_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpckhbw_opx, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckhwd_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 4;
    for (size_t i = 0; i < 8; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckhwd_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 8;
    for (size_t i = 0; i < 16; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckhwd_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 4;
    for (size_t i = 0; i < 8; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckhwd_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 8;
    for (size_t i = 0; i < 16; i += 4) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 2] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 3] = src_tags[j];
        j++;
    }
}

void ins_punpckhwd_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            R2R_CALL(r2r_punpckhwd_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpckhwd_opx, reg_dst, reg_src);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            M2R_CALL(m2r_punpckhwd_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpckhwd_opx, reg_dst);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckhdq_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 4;
    for (size_t i = 0; i < 8; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckhdq_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 8;
    for (size_t i = 0; i < 16; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckhdq_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    tag_t dst_tags[] = R64TAG(dst);

    size_t j = 4;
    for (size_t i = 0; i < 8; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckhdq_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 8;
    for (size_t i = 0; i < 16; i += 8) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 4] = src_tags[j];
        j++;
        RTAG[dst][i + 1] = dst_tags[j];
        RTAG[dst][i + 5] = src_tags[j];
        j++;
        RTAG[dst][i + 2] = dst_tags[j];
        RTAG[dst][i + 6] = src_tags[j];
        j++;
        RTAG[dst][i + 3] = dst_tags[j];
        RTAG[dst][i + 7] = src_tags[j];
        j++;
    }
}

void ins_punpckhdq_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_mm(reg_dst)) {
            R2R_CALL(r2r_punpckhdq_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpckhdq_opx, reg_dst, reg_src);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_mm(reg_dst)) {
            M2R_CALL(m2r_punpckhdq_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpckhdq_opx, reg_dst);
        }  else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_punpckhqdq_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 8;
    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 8] = src_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_punpckhqdq_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t dst_tags[] = R128TAG(dst);

    size_t j = 8;
    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = dst_tags[j];
        RTAG[dst][i + 8] = src_tags[j];
        j++;
    }
}

void ins_punpckhqdq_op(INS ins) {
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_punpckhqdq_opx, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_punpckhqdq_opx, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_vpunpckhqdq_opx(THREADID tid, uint32_t dst, uint32_t src1, uint32_t src2) {
    tag_t src1_tags[] = R128TAG(src1);
    tag_t src2_tags[] = R128TAG(src2);

    size_t j = 8;
    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = src2_tags[j];
        RTAG[dst][i + 8] = src1_tags[j];
        j++;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_vpunpckhqdq_opx(THREADID tid, uint32_t dst, uint32_t src1, ADDRINT src2) {
    tag_t src2_tags[] = M128TAG(src2);
    tag_t src1_tags[] = R128TAG(src1);

    size_t j = 8;
    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = src2_tags[j];
        RTAG[dst][i + 8] = src1_tags[j];
        j++;
    }
}

void ins_vpunpckhqdq_op(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src1 = INS_OperandReg(ins, OP_1);
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_src2 = INS_OperandReg(ins, OP_2);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_vpunpckhqdq_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_UINT32, REG_INDX(reg_src2),
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_vpunpckhqdq_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src1),
                           IARG_MEMORYREAD_EA,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}


static void PIN_FAST_ANALYSIS_CALL r2r_pshufd_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm, uint32_t byteCount, uint32_t chunkSize, bool isVex128) {
    tag_t src_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = RTAG[reg_src][i];
    }

    size_t choice0 = imm & 0x3; // imm[1:0]
    size_t choice1 = (imm & 0xc) >> 2; // imm[3:2]
    size_t choice2 = (imm & 0x30) >> 4; // imm[5:4]
    size_t choice3 = (imm & 0xc0) >> 6; // imm[7:6]

    for (size_t i = 0; i < chunkSize; ++i)
    {
        RTAG[reg_dst][i] = src_tags[i + (choice0 * chunkSize)];
        RTAG[reg_dst][i + 4] = src_tags[i + (choice1 * chunkSize)];
        RTAG[reg_dst][i + 8] = src_tags[i + (choice2 * chunkSize)];
        RTAG[reg_dst][i + 12] = src_tags[i + (choice3 * chunkSize)];
    }

    if (isVex128)
    {
        for (size_t i = 16; i < 32; ++i)
        {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_pshufd_op(THREADID tid, uint32_t reg_dst, uint64_t addr, uint32_t imm, uint32_t byteCount, uint32_t chunkSize, bool isVex128) {
    tag_t src_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = MTAG(addr + i);
    }

    size_t choice0 = imm & 0x3; // imm[1:0]
    size_t choice1 = (imm & 0xc) >> 2; // imm[3:2]
    size_t choice2 = (imm & 0x30) >> 4; // imm[5:4]
    size_t choice3 = (imm & 0xc0) >> 6; // imm[7:6]

    for (size_t i = 0; i < chunkSize; ++i)
    {
        RTAG[reg_dst][i] = src_tags[i + (choice0 * chunkSize)];
        RTAG[reg_dst][i + 4] = src_tags[i + (choice1 * chunkSize)];
        RTAG[reg_dst][i + 8] = src_tags[i + (choice2 * chunkSize)];
        RTAG[reg_dst][i + 12] = src_tags[i + (choice3 * chunkSize)];
    }

    if (isVex128)
    {
        for (size_t i = 16; i < 32; ++i)
        {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
    }
}

void ins_pshufd_op(INS ins) {
    REG reg_dst, reg_src;
    uint32_t imm = INS_OperandImmediate(ins, OP_2) & 0xff;
    uint32_t chunkSize = 4;
    if (INS_OperandIsMemory(ins, OP_1)) {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, imm,
                           IARG_UINT32, 16,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, false,
                           IARG_END);
        } else if (REG_is_ymm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, imm,
                           IARG_UINT32, 32,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, false,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, 16,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, false,
                           IARG_END);
        } else if (REG_is_ymm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, 32,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, false,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void ins_vpshufd_op(INS ins) {
    REG reg_dst, reg_src;
    uint32_t imm = INS_OperandImmediate(ins, OP_2) & 0xff;
    uint32_t chunkSize = 4;
    if (INS_OperandIsMemory(ins, OP_1)) {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, imm,
                           IARG_UINT32, 16,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, true,
                           IARG_END);
        } else if (REG_is_ymm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, imm,
                           IARG_UINT32, 32,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, false,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, 16,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, true,
                           IARG_END);
        } else if (REG_is_ymm(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_pshufd_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, 32,
                           IARG_UINT32, chunkSize,
                           IARG_BOOL, false,
                           IARG_END);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL _pslldq_opx(THREADID tid, uint32_t reg, uint32_t imm) {
    // If the value specified by the count operand is greater than 15, the destination operand is set to all 0s.
    if (imm > 15) {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[] = R128TAG(reg);

    for (size_t i = 0; i < imm; i++) {
        RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = imm; i < 16; i++) {
        RTAG[reg][i] = save_tags[i - imm];
    }
}

void ins_pslldq_op(INS ins) {
    REG reg = INS_OperandReg(ins, OP_0);
    UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_1);
    if (REG_is_xmm(reg)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_pslldq_opx,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg),
                       IARG_UINT32, imm,
                       IARG_END);
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}

static void PIN_FAST_ANALYSIS_CALL _vpslldq_opx(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm) {
    // If the value specified by the count operand is greater than 15, the destination operand is set to all 0s.
    if (imm > 15) {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t src_tags[] = R128TAG(reg_src);

    for (size_t i = 0; i < imm; i++) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = imm; i < 16; i++) {
        RTAG[reg_dst][i] = src_tags[i - imm];
    }
}

static void PIN_FAST_ANALYSIS_CALL _vpslldq_opy(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm) {
    // If the value specified by the count operand is greater than 15, the destination operand is set to all 0s.
    if (imm > 15) {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t src_tags[] = R256TAG(reg_src);

    for (size_t i = 0; i < imm; i++) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = imm; i < 32; i++) {
        RTAG[reg_dst][i] = src_tags[i - imm];
    }

    // For YMM: the count operand applies to both the low and high 128-bit lanes
    for (size_t i = 16; i < 16 + imm; i++) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = 16 + imm; i < 32; i++) {
        RTAG[reg_dst][i] = src_tags[i - imm];
    }
}

void ins_vpslldq_op(INS ins) {
    // only support AVX(2)
    if (INS_OperandIsMemory(ins, OP_1)) {
        return;
    }

    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src = INS_OperandReg(ins, OP_1);
    UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_2);
    if (REG_is_xmm(reg_dst)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpslldq_opx,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, REG_INDX(reg_src),
                       IARG_UINT32, imm,
                       IARG_END);
    } else if (REG_is_ymm(reg_dst)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpslldq_opy,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, REG_INDX(reg_src),
                       IARG_UINT32, imm,
                       IARG_END);
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}

static void PIN_FAST_ANALYSIS_CALL _vpsrldq_opx(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm) {
    // If the value specified by the count operand is greater than 15, the destination operand is set to all 0s.
    if (imm > 15) {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[] = R128TAG(reg_src);

    for (size_t i = 15; i > (15 - imm); i--) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = (15 - imm); i <= 15; i--) {
        RTAG[reg_dst][i] = save_tags[i + imm];
    }
}

static void PIN_FAST_ANALYSIS_CALL _vpsrldq_opy(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm) {
    // If the value specified by the count operand is greater than 15, the destination operand is set to all 0s.
    if (imm > 15) {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[] = R256TAG(reg_src);

    for (size_t i = 15; i > (15 - imm); i--) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = (15 - imm); i <= 15; i--) {
        RTAG[reg_dst][i] = save_tags[i + imm];
    }

    // For YMM: the count operand applies to both the low and high 128-bit lanes
    for (size_t i = 31; i > (31 - imm); i--) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = (31 - imm); i >= 16; i--) {
        RTAG[reg_dst][i] = save_tags[i + imm];
    }
}

void ins_vpsrldq_op(INS ins) {
    // only support AVX(2)
    if (INS_OperandIsMemory(ins, OP_1)) {
        return;
    }

    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src = INS_OperandReg(ins, OP_1);
    UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_2);
    if (REG_is_xmm(reg_dst)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpsrldq_opx,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, REG_INDX(reg_src),
                       IARG_UINT32, imm,
                       IARG_END);
    } else if (REG_is_ymm(reg_dst)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_vpsrldq_opy,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg_dst),
                       IARG_UINT32, REG_INDX(reg_src),
                       IARG_UINT32, imm,
                       IARG_END);
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}

static void PIN_FAST_ANALYSIS_CALL _psrldq_opx(THREADID tid, uint32_t reg, uint32_t imm) {
    // If the value specified by the count operand is greater than 15, the destination operand is set to all 0s.
    if (imm > 15) {
        for (size_t i = 0; i < 16; i++) {
            RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[] = R128TAG(reg);

    // Shifts the destination operand (first operand) to the right by the number of bytes specified in the count operand (second operand).
    // The empty high-order bytes are cleared (set to all 0s).
    for (size_t i = 15; i > (15 - imm); i--) {
        RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
    }

    for (size_t i = (15 - imm); i <= 15; i--) {
        RTAG[reg][i] = save_tags[i + imm];
    }
}

void ins_psrldq_op(INS ins) {
    REG reg = INS_OperandReg(ins, OP_0);
    UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_1);
    if (REG_is_xmm(reg)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_psrldq_opx,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                       IARG_UINT32, REG_INDX(reg),
                       IARG_UINT32, imm,
                       IARG_END);
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}



static void PIN_FAST_ANALYSIS_CALL r_psllx_op(THREADID tid, uint32_t reg_dst, uint32_t imm, uint32_t chunkSize, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }
    // If the value specified by the count operand is greater than 15 (for words), 31 (for doublewords),
    // or 63 (for a quadword), then the destination operand is set to all 0s.
    if (imm > (chunkSize * 8) - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        save_tags[i] = RTAG[reg_dst][i];
    }
    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Iterate over words / dwords / qwords
    for (size_t k = 0; k < byteCount / chunkSize; k++) {
        // If the bitshift uses whole bytes
        // The whole bytes can be zeroed
        for (size_t i = 0; i < (uint32_t)res.quot; i++) {
            RTAG[reg_dst][k * chunkSize + i] = tag_traits<tag_t>::cleared_val;
        }
        if (res.rem == 0) {
            // Shift the tainted values
            for (size_t i = res.quot; i < chunkSize; i++) {
                RTAG[reg_dst][k * chunkSize + i] = save_tags[k * chunkSize + i - res.quot];
            }
        } else { // We need to combine taint from bytes
            // The rest has to be combined
            RTAG[reg_dst][k * chunkSize + res.quot] = save_tags[k * chunkSize];
            for (size_t i = res.quot + 1; i < chunkSize; i++) {
                RTAG[reg_dst][k * chunkSize + i] = tag_combine(
                        save_tags[k * chunkSize + i - res.quot], save_tags[k * chunkSize + i - res.quot - 1]);
            }
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL mr_psllx_opq(THREADID tid, uint32_t reg_dst, uint64_t addr, uint32_t chunkSize, uint32_t byteCount) {
    uint64_t imm = *((uint64_t *)(addr));

    r_psllx_op(tid, reg_dst, (uint32_t)imm, chunkSize, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL mr_psllx_opx(THREADID tid, uint32_t reg_dst, uint64_t addr, uint32_t chunkSize, uint32_t byteCount) {
    // If the count operand is a memory address, 128 bits are loaded but the upper 64 bits are ignored.
    uint64_t imm = *((uint64_t *)(addr + sizeof(uint64_t)));

    r_psllx_op(tid, reg_dst, (uint32_t)imm, chunkSize, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL rr_psllx_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_src, uint32_t chunkSize, uint32_t byteCount) {
    // The upper 64 bits of the register are ignored
    uint64_t imm = *((uint64_t *)(reg_src));

    r_psllx_op(tid, reg_dst, (uint32_t)imm, chunkSize, byteCount);
}

void ins_psllx_op(INS ins, uint32_t chunkSize) {
    // chunkSize 2 for psllw, 4 for pslld, 8 for psllq
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_mm(reg_dst)) {
        uint32_t byteCount = 8;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_psllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_psllx_opq,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (REG_is_mm(INS_OperandReg(ins, OP_1))) {
            REG reg_src = INS_OperandReg(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_psllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_src,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        }
    } else if (REG_is_xmm(reg_dst)) {
        uint32_t byteCount = 16;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_psllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_psllx_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (REG_is_xmm(INS_OperandReg(ins, OP_1))) {
            REG reg_src = INS_OperandReg(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_psllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_src,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        }
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}

static void PIN_FAST_ANALYSIS_CALL r_vpsllx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm, uint32_t chunkSize, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }
    // If the value specified by the count operand is greater than 15 (for words), 31 (for doublewords),
    // or 63 (for a quadword), then the destination operand is set to all 0s.
    if (imm > (chunkSize * 8) - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
            RTAG[reg_src][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        save_tags[i] = RTAG[reg_src][i];
    }
    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Iterate over words / dwords / qwords
    for (size_t k = 0; k < byteCount / chunkSize; k++) {
        // If the bitshift uses whole bytes
        // The whole bytes can be zeroed
        for (size_t i = 0; i < (uint32_t)res.quot; i++) {
            RTAG[reg_src][k * chunkSize + i] = tag_traits<tag_t>::cleared_val;
        }
        if (!res.rem) {
            // Shift the tainted values
            for (size_t i = res.quot; i < chunkSize; i++) {
                RTAG[reg_src][i] = save_tags[k * chunkSize + i - res.quot];
            }
        } else { // We need to combine taint from bytes
            // The rest has to be combined
            RTAG[reg_src][k * chunkSize + res.quot] = save_tags[k * chunkSize];
            for (size_t i = res.quot + 1; i < chunkSize; i++) {
                RTAG[reg_src][i] = tag_combine(
                        save_tags[k * chunkSize + i - res.quot], save_tags[k * chunkSize + i - res.quot - 1]);
            }
        }
    }

    // Copy the resulting taint values
    for (size_t i = 0; i < byteCount; i++) {
        RTAG[reg_dst][i] = RTAG[reg_src][i];
    }
}

static void PIN_FAST_ANALYSIS_CALL mr_vpsllx_opx(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint64_t addr, uint32_t chunkSize, uint32_t byteCount) {
    // If the count operand is a memory address, 128 bits are loaded but the upper 64 bits are ignored.
    uint64_t imm = *((uint64_t *)(addr + sizeof(uint64_t)));

    r_vpsllx_op(tid, reg_dst, reg_src, (uint32_t)imm, chunkSize, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL mr_vpsllx_opy(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint64_t addr, uint32_t chunkSize, uint32_t byteCount) {
    // If the count operand is a memory address, 256 bits are loaded but the upper 64 + 128 bits are ignored.
    uint64_t imm = *((uint64_t *)(addr + 3*sizeof(uint64_t)));

    r_vpsllx_op(tid, reg_dst, reg_src, (uint32_t)imm, chunkSize, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL rr_vpsllx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint8_t *reg_src2, uint32_t chunkSize, uint32_t byteCount) {
    // The upper 64 + 128 bits of the register are ignored
    uint64_t imm = *((uint64_t *)(reg_src2));

    r_vpsllx_op(tid, reg_dst, reg_src, (uint32_t)imm, chunkSize, byteCount);
}

void ins_vpsllx_op(INS ins, uint32_t chunkSize) {
    // chunkSize 2 for vpsllw, 4 for vpslld, 8 for vpsllq
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_xmm(reg_dst)) {
        uint32_t byteCount = 16;
        if (INS_OperandIsImmediate(ins, OP_2)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_vpsllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_2)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_vpsllx_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (REG_is_xmm(INS_OperandReg(ins, OP_2))) {
            REG reg_src2 = INS_OperandReg(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_vpsllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_REG_CONST_REFERENCE, reg_src2,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        }
    } else if (REG_is_ymm(reg_dst)) {
        uint32_t byteCount = 32;
        if (INS_OperandIsImmediate(ins, OP_2)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_vpsllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_2)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_vpsllx_opy,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (REG_is_ymm(INS_OperandReg(ins, OP_2))) {
            REG reg_src2 = INS_OperandReg(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_vpsllx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_REG_CONST_REFERENCE, reg_src2,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        }
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}


static void PIN_FAST_ANALYSIS_CALL r_psrlx_op(THREADID tid, uint32_t reg_dst, uint32_t imm, uint32_t chunkSize, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }
    // If the value specified by the count operand is greater than 15 (for words), 31 (for doublewords),
    // or 63 (for a quadword), then the destination operand is set to all 0s.
    if (imm > (chunkSize * 8) - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        save_tags[i] = RTAG[reg_dst][i];
    }
    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Iterate over words / dwords / qwords
    for (size_t k = 0; k < byteCount / chunkSize; k++) {
        uint32_t chunkStart = k * chunkSize;
        // If the bitshift uses whole bytes
        // The whole bytes can be zeroed
        for (size_t i = chunkSize - 1; i >= chunkSize - (uint32_t)res.quot; i--) {
            RTAG[reg_dst][chunkStart + i] = tag_traits<tag_t>::cleared_val;
        }
        if (res.rem == 0) {
            // Shift the tainted values
            for (size_t i = chunkSize - 1 - res.quot; i < chunkSize; i--) {
                RTAG[reg_dst][chunkStart + i] = save_tags[chunkStart + i + res.quot];
            }

//            for (size_t i = chunkSize - 1 - res.quot + 1; i > 0; i--) {
//                RTAG[reg_dst][chunkStart + i - 1] = save_tags[chunkStart + i + res.quot - 1];
//            }
        } else { // We need to combine taint from bytes
            // The rest has to be combined
            RTAG[reg_dst][chunkStart + chunkSize - 1 - res.quot] = save_tags[(k + 1) * chunkSize - 1];
            for (size_t i = chunkSize - 1 - res.quot - 1; i < chunkSize; i--) {
                RTAG[reg_dst][chunkStart + i] = tag_combine(
                        save_tags[chunkStart + i + res.quot], save_tags[chunkStart + i + res.quot + 1]);
            }
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL mr_psrlx_opq(THREADID tid, uint32_t reg_dst, uint64_t addr, uint32_t chunkSize, uint32_t byteCount) {
    uint64_t imm = *((uint64_t *)(addr));

    r_psrlx_op(tid, reg_dst, (uint32_t)imm, chunkSize, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL rr_psrlx_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_src, uint32_t chunkSize, uint32_t byteCount) {
    uint64_t imm = *((uint64_t *)(reg_src));

    r_psrlx_op(tid, reg_dst, (uint32_t)imm, chunkSize, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL mr_psrlx_opx(THREADID tid, uint32_t reg_dst, uint64_t addr, uint32_t chunkSize, uint32_t byteCount) {
    // If the count operand is a memory address, 128 bits are loaded but the upper 64 bits are ignored.
    uint64_t imm = *((uint64_t *)(addr + sizeof(uint64_t)));

    r_psrlx_op(tid, reg_dst, (uint32_t)imm, chunkSize, byteCount);
}

void ins_psrlx_op(INS ins, uint32_t chunkSize) {
    // chunkSize 2 for psrlw, 4 for psrld, 8 for psrlq
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_mm(reg_dst)) {
        uint32_t byteCount = 8;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_psrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_psrlx_opq,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (REG_is_mm(INS_OperandReg(ins, OP_1))) {
            REG reg_src = INS_OperandReg(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_psrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_src,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        }
    } else if (REG_is_xmm(reg_dst)) {
        uint32_t byteCount = 16;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_psrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_1)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_psrlx_opx,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_END);
        } else if (REG_is_xmm(INS_OperandReg(ins, OP_1))) {
            REG reg_src = INS_OperandReg(ins, OP_1);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_psrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_REG_CONST_REFERENCE, reg_src,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, byteCount,
                           IARG_END);
        }
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}

static void PIN_FAST_ANALYSIS_CALL r_vpsrlx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm, uint32_t chunkSize, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }
    // If the value specified by the count operand is greater than 15 (for words), 31 (for doublewords),
    // or 63 (for a quadword), then the destination operand is set to all 0s.
    if (imm > (chunkSize * 8) - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
            RTAG[reg_src][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t save_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        save_tags[i] = RTAG[reg_src][i];
    }
    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Iterate over words / dwords / qwords
    for (size_t k = 0; k < byteCount / chunkSize; k++) {
        uint32_t chunkStart = k * chunkSize;
        // If the bitshift uses whole bytes
        // The whole bytes can be zeroed
        for (size_t i = chunkSize - 1; i >= chunkSize - (uint32_t)res.quot; i--) {
            RTAG[reg_src][chunkStart + i] = tag_traits<tag_t>::cleared_val;
        }
        if (res.rem == 0) {
            // Shift the tainted values
            for (size_t i = chunkSize - 1 - res.quot; i < chunkSize; i--) {
                RTAG[reg_src][chunkStart + i] = save_tags[chunkStart + i + res.quot];
            }
        } else { // We need to combine taint from bytes
            // The rest has to be combined
            RTAG[reg_src][chunkStart + chunkSize - 1 - res.quot] = save_tags[(k + 1) * chunkSize - 1];
            for (size_t i = chunkSize - 1 - res.quot - 1; i < chunkSize; i--) {
                RTAG[reg_src][chunkStart + i] = tag_combine(
                        save_tags[chunkStart + i + res.quot], save_tags[chunkStart + i + res.quot + 1]);
            }
        }
    }

    // Copy the resulting taint values
    for (size_t i = 0; i < byteCount; i++) {
        RTAG[reg_dst][i] = RTAG[reg_src][i];
    }
}

static void PIN_FAST_ANALYSIS_CALL mr_vpsrlx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint64_t addr, uint32_t chunkSize, uint32_t byteCount) {
    // If the count operand is a memory address, 256 bits are loaded but the upper 64 + 128 bits are ignored.
    uint64_t imm = *((uint64_t *)(addr + 3*sizeof(uint64_t)));

    r_vpsrlx_op(tid, reg_dst, reg_src, (uint32_t)imm, chunkSize, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL rr_vpsrlx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint8_t *reg_src2, uint32_t chunkSize, uint32_t byteCount) {
    // The upper 64 + 128 bits of the register are ignored
    uint64_t imm = *((uint64_t *)(reg_src2));

    r_vpsrlx_op(tid, reg_dst, reg_src, (uint32_t)imm, chunkSize, byteCount);
}

void ins_vpsrlx_op(INS ins, uint32_t chunkSize) {
    // chunkSize 2 for vpsrlw, 4 for vpsrld, 8 for vpsrlq
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_xmm(reg_dst)) {
        if (INS_OperandIsImmediate(ins, OP_2)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_vpsrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, 16,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_2)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_vpsrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, 16,
                           IARG_END);
        } else if (REG_is_xmm(INS_OperandReg(ins, OP_2))) {
            REG reg_src2 = INS_OperandReg(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_vpsrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_REG_CONST_REFERENCE, reg_src2,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, 16,
                           IARG_END);
        }
    } else if (REG_is_ymm(reg_dst)) {
        if (INS_OperandIsImmediate(ins, OP_2)) {
            UINT32 imm = (UINT32)INS_OperandImmediate(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_vpsrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, 32,
                           IARG_END);
        } else if (INS_OperandIsMemory(ins, OP_2)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mr_vpsrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, 32,
                           IARG_END);
        } else if (REG_is_ymm(INS_OperandReg(ins, OP_2))) {
            REG reg_src2 = INS_OperandReg(ins, OP_2);
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rr_vpsrlx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_REG_CONST_REFERENCE, reg_src2,
                           IARG_UINT32, chunkSize,
                           IARG_UINT32, 32,
                           IARG_END);
        }
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_shld_op(THREADID tid, uint32_t reg_src, uint32_t reg_dst, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t src_tags[byteCount];
    tag_t dst_tags[byteCount];

    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = RTAG[reg_src][i];
        dst_tags[i] = RTAG[reg_dst][i];
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);
    // If the bitshift uses whole bytes
    // The whole bytes can be copied from src
    for (size_t i = 0; i < (uint32_t)res.quot; i++) {
        RTAG[reg_dst][i] = src_tags[i];
    }
    if (res.rem == 0) {
        // Shift the dst values
        for (size_t i = res.quot; i < byteCount; i++) {
            RTAG[reg_dst][i] = dst_tags[i - res.quot];
        }
    } else { // We need to combine taint from bytes
        // The rest has to be combined
        RTAG[reg_dst][res.quot] = src_tags[0];
        for (size_t i = res.quot + 1; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[i - res.quot], dst_tags[i - res.quot - 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_reg_shld_op(THREADID tid, uint32_t reg_src, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r2r_shld_op(tid, reg_src, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL r2m_shld_op(THREADID tid, uint32_t reg_src, uint64_t addr, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t src_tags[byteCount];
    tag_t dst_tags[byteCount];

    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = RTAG[reg_src][i];
        dst_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);
    // If the bitshift uses whole bytes
    // The whole bytes can be copied from src
    for (size_t i = 0; i < (uint32_t)res.quot; i++) {
        tagmap_setb(addr + i, src_tags[i]);
    }
    if (res.rem == 0) {
        // Shift the dst values
        for (size_t i = res.quot; i < byteCount; i++) {
            tagmap_setb(addr + i, dst_tags[i - res.quot]);
        }
    } else { // We need to combine taint from bytes
        // The rest has to be combined
        tagmap_setb(addr + res.quot, src_tags[0]);
        for (size_t i = res.quot + 1; i < byteCount; i++) {
            tagmap_setb(addr + i, tag_combine(dst_tags[i - res.quot], dst_tags[i - res.quot - 1]));
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2m_reg_shld_op(THREADID tid, uint32_t reg_src, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r2m_shld_op(tid, reg_src, addr, imm, byteCount);
}

void ins_shld_op(INS ins) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (INS_OperandIsImmediate(ins, OP_2)) {
        UINT32 imm = INS_OperandImmediate(ins, OP_2);

        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        } else {
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        }

    } else if (REG_is_Lower8(INS_OperandReg(ins, OP_2))) {
        REG reg_cnt = INS_OperandReg(ins, OP_2);

        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_reg_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_reg_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_reg_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        } else {
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_reg_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_reg_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_reg_shld_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        }

    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}


static void PIN_FAST_ANALYSIS_CALL r2r_shrd_op(THREADID tid, uint32_t reg_src, uint32_t reg_dst, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t src_tags[byteCount];
    tag_t dst_tags[byteCount];

    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = RTAG[reg_src][i];
        dst_tags[i] = RTAG[reg_dst][i];
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);
    // If the bitshift uses whole bytes
    // The whole bytes can be copied from src
    for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
        RTAG[reg_dst][i] = src_tags[i];
    }
    if (res.rem == 0) {
        // Shift the dst values
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            RTAG[reg_dst][i] = dst_tags[i + res.quot];
        }
    } else { // We need to combine taint from bytes
        // The rest has to be combined
        RTAG[reg_dst][byteCount - res.quot - 1] = src_tags[byteCount - 1];
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[i + res.quot], dst_tags[i + res.quot + 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2r_reg_shrd_op(THREADID tid, uint32_t reg_src, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r2r_shrd_op(tid, reg_src, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL r2m_shrd_op(THREADID tid, uint32_t reg_src, uint64_t addr, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t src_tags[byteCount];
    tag_t dst_tags[byteCount];

    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = RTAG[reg_src][i];
        dst_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);
    // If the bitshift uses whole bytes
    // The whole bytes can be copied from src
    for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
        tagmap_setb(addr + i, src_tags[i]);
    }
    if (res.rem == 0) {
        // Shift the dst values
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            tagmap_setb(addr + i, dst_tags[i + res.quot]);
        }
    } else { // We need to combine taint from bytes
        // The rest has to be combined
        tagmap_setb(addr + (byteCount - res.quot - 1), src_tags[byteCount - 1]);
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            tagmap_setb(addr + i, tag_combine(dst_tags[i + res.quot], dst_tags[i + res.quot + 1]));
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r2m_reg_shrd_op(THREADID tid, uint32_t reg_src, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r2m_shrd_op(tid, reg_src, addr, imm, byteCount);
}

void ins_shrd_op(INS ins) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (INS_OperandIsImmediate(ins, OP_2)) {
        UINT32 imm = INS_OperandImmediate(ins, OP_2);

        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        } else {
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        }

    } else if (REG_is_Lower8(INS_OperandReg(ins, OP_2))) {
        REG reg_cnt = INS_OperandReg(ins, OP_2);

        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_reg_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_reg_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_reg_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        } else {
            if (REG_is_gr64(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_reg_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_reg_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_src)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_reg_shrd_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_src),
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            }
        }

    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}

static void PIN_FAST_ANALYSIS_CALL r_shl_op(THREADID tid, uint32_t reg_dst, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = RTAG[reg_dst][i];
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Clear all whole bytes
    for (size_t i = 0; i < (uint32_t)res.quot; i++) {
        RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
    }

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        // Shift the tainted values
        for (size_t i = res.quot; i < byteCount; i++) {
            RTAG[reg_dst][i] = dst_tags[i - res.quot];
        }
    } else { // We need to combine the taint
        RTAG[reg_dst][res.quot] = dst_tags[0];
        for (size_t i = res.quot + 1; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[i - res.quot], dst_tags[i - res.quot - 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r_shl_op_upper8(THREADID tid, uint32_t reg_dst, uint32_t imm) {
    if (imm > 7) {
        RTAG[reg_dst][1] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_shl_op_lower8(THREADID tid, uint32_t reg_dst, uint32_t imm) {
    if (imm > 7) {
        RTAG[reg_dst][0] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL m_shl_op(THREADID tid, uint64_t addr, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Clear all whole bytes
    for (size_t i = 0; i < (uint32_t)res.quot; i++) {
        tagmap_setb(addr + i, tag_traits<tag_t>::cleared_val);
    }

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        // Shift the tainted values
        for (size_t i = res.quot; i < byteCount; i++) {
            tagmap_setb(addr + i, dst_tags[i - res.quot]);
        }
    } else { // We need to combine the taint
        tagmap_setb(addr + res.quot, dst_tags[0]);
        for (size_t i = res.quot + 1; i < byteCount; i++) {
            tagmap_setb(addr + i, tag_combine(dst_tags[i - res.quot], dst_tags[i - res.quot - 1]));
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m_shl_op_8(THREADID tid, uint64_t addr, uint32_t imm) {
    if (imm > 7) {
        tagmap_setb(addr, tag_traits<tag_t>::cleared_val);
    }
}

static void PIN_FAST_ANALYSIS_CALL r_reg_shl_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r_shl_op(tid, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL r_reg_shl_op_upper8(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r_shl_op_upper8(tid, reg_dst, imm);
}

static void PIN_FAST_ANALYSIS_CALL r_reg_shl_op_lower8(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r_shl_op_lower8(tid, reg_dst, imm);
}

static void PIN_FAST_ANALYSIS_CALL m_reg_shl_op(THREADID tid, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    m_shl_op(tid, addr, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL m_reg_shl_op_8(THREADID tid, uint64_t addr, uint8_t *reg_cnt) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    m_shl_op_8(tid, addr, imm);
}

void ins_shl_op(INS ins) {
    if (INS_OperandIsReg(ins, OP_1)) {
        REG reg_cnt = INS_OperandReg(ins, OP_1);
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (REG_is_Lower8(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shl_op_lower8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shl_op_upper8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shl_op_8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_END);
            }
        }
    } else {
        uint32_t imm = 1; // If no other immediate or value from RCX are used, then the second operand is 1
        if (INS_OperandIsImmediate(ins, OP_1)) {
            imm = INS_OperandImmediate(ins, OP_1);
        }
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (REG_is_Lower8(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shl_op_lower8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shl_op_upper8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shl_op_8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_END);
            }
        }
    }
}



static void PIN_FAST_ANALYSIS_CALL r_shr_op(THREADID tid, uint32_t reg_dst, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    if (imm > byteCount * 8 - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_traits<tag_t>::cleared_val;
        }
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = RTAG[reg_dst][i];
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
            RTAG[reg_dst][i] = dst_tags[i + res.quot];
        }
    } else { // We need to combine the taint
        RTAG[reg_dst][byteCount - res.quot - 1] = dst_tags[byteCount - 1];
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[i + res.quot], dst_tags[i + res.quot + 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r_shr_op_upper8(THREADID tid, uint32_t reg_dst, uint32_t imm) {
    if (imm > 7) {
        RTAG[reg_dst][1] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL r_shr_op_lower8(THREADID tid, uint32_t reg_dst, uint32_t imm) {
    if (imm > 7) {
        RTAG[reg_dst][0] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL m_shr_op(THREADID tid, uint64_t addr, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    if (imm > byteCount * 8 - 1) {
        for (size_t i = 0; i < byteCount; i++) {
            tagmap_setb(addr + i, tag_traits<tag_t>::cleared_val);
        }
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // Clear all whole bytes
    for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
        tagmap_setb(addr + i, tag_traits<tag_t>::cleared_val);
    }

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        // Shift the tainted values
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            tagmap_setb(addr + i, dst_tags[i + res.quot]);
        }
    } else { // We need to combine the taint
        tagmap_setb(addr +(byteCount - res.quot - 1), dst_tags[byteCount - 1]);
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            tagmap_setb(addr + i, tag_combine(dst_tags[i + res.quot], dst_tags[i + res.quot + 1]));
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m_shr_op_8(THREADID tid, uint64_t addr, uint32_t imm) {
    if (imm > 7) {
        tagmap_setb(addr, tag_traits<tag_t>::cleared_val);
    }
}

static void PIN_FAST_ANALYSIS_CALL r_reg_shr_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r_shr_op(tid, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL r_reg_shr_op_upper8(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r_shr_op_upper8(tid, reg_dst, imm);
}

static void PIN_FAST_ANALYSIS_CALL r_reg_shr_op_lower8(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    r_shr_op_lower8(tid, reg_dst, imm);
}

static void PIN_FAST_ANALYSIS_CALL m_reg_shr_op(THREADID tid, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    m_shr_op(tid, addr, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL m_reg_shr_op_8(THREADID tid, uint64_t addr, uint8_t *reg_cnt) {
    uint32_t imm = (uint32_t)(*(reg_cnt));

    m_shr_op_8(tid, addr, imm);
}

void ins_shr_op(INS ins) {
    if (INS_OperandIsReg(ins, OP_1)) {
        REG reg_cnt = INS_OperandReg(ins, OP_1);
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (REG_is_Lower8(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shr_op_lower8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_shr_op_upper8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_shr_op_8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_END);
            }
        }
    } else {
        uint32_t imm = 1; // If no other immediate or value from RCX are used, then the second operand is 1
        if (INS_OperandIsImmediate(ins, OP_1)) {
            imm = INS_OperandImmediate(ins, OP_1);
        }
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (REG_is_Lower8(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shr_op_lower8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_END);
            } else {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_shr_op_upper8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_shr_op_8,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_END);
            }
        }
    }
}


static void PIN_FAST_ANALYSIS_CALL r_rol_op(THREADID tid, uint32_t reg_dst, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = RTAG[reg_dst][i];
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        for (size_t i = 0; i < (uint32_t)res.quot; i++) {
            RTAG[reg_dst][i] = dst_tags[i + (byteCount - res.quot)];
        }
        for (size_t i = res.quot; i < byteCount; i++) {
            RTAG[reg_dst][i] = dst_tags[i - res.quot];
        }
    } else { // We need to combine the taint
        for (size_t i = 0; i < (uint32_t)res.quot; i++) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[byteCount - res.quot + i], dst_tags[byteCount - res.quot + i - 1]);
        }
        RTAG[reg_dst][res.quot] = tag_combine(dst_tags[byteCount - 1], dst_tags[0]);
        for (size_t i = res.quot + 1; i < byteCount; i++) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[i - res.quot], dst_tags[i - res.quot - 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r_reg_rol_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;

    r_rol_op(tid, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL m_rol_op(THREADID tid, uint64_t addr, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        for (size_t i = 0; i < (uint32_t)res.quot; i++) {
            tagmap_setb(addr + i, dst_tags[i + (byteCount - res.quot)]);
        }
        for (size_t i = res.quot; i < byteCount; i++) {
            tagmap_setb(addr + i, dst_tags[i - res.quot]);
        }
    } else { // We need to combine the taint
        for (size_t i = 0; i < (uint32_t)res.quot; i++) {
            tagmap_setb(addr + i, tag_combine(dst_tags[byteCount - res.quot + i], dst_tags[byteCount - res.quot + i - 1]));
        }
        tagmap_setb(addr + res.quot, tag_combine(dst_tags[byteCount - 1], dst_tags[0]));
        for (size_t i = res.quot + 1; i < byteCount; i++) {
            tagmap_setb(addr + i, tag_combine(dst_tags[i - res.quot], dst_tags[i - res.quot - 1]));
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m_reg_rol_op(THREADID tid, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;

    m_rol_op(tid, addr, imm, byteCount);
}


void ins_rol_op(INS ins) {
    BOOL hasRepPrefix = INS_RepPrefix(ins);
    if (INS_OperandIsReg(ins, OP_1)) {
        REG reg_cnt = INS_OperandReg(ins, OP_1);
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                 // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rol_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rol_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rol_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_UINT32, 1,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        }
    } else {
        uint32_t imm = 1; // If no other immediate or value from RCX are used, then the second operand is 1
        uint32_t mask = 0;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            if (hasRepPrefix) {
                mask = 0x3F;
            } else {
                mask = 0x1F;
            }
            imm = mask & INS_OperandImmediate(ins, OP_1);
        }
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_UINT32, imm,
//                               IARG_UINT32, 1,
//                               IARG_END);
            }
        }
    }
}


static void PIN_FAST_ANALYSIS_CALL r_reg_rcl_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;
    imm++;

    r_rol_op(tid, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL m_reg_rcl_op(THREADID tid, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;
    imm++;

    m_rol_op(tid, addr, imm, byteCount);
}

void ins_rcl_op(INS ins) {
    BOOL hasRepPrefix = INS_RepPrefix(ins);
    if (INS_OperandIsReg(ins, OP_1)) {
        REG reg_cnt = INS_OperandReg(ins, OP_1);
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                 // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcl_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcl_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcl_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcl_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_UINT32, 1,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        }
    } else {
        uint32_t imm = 1; // If no other immediate or value from RCX are used, then the second operand is 1
        uint32_t mask = 0;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            if (hasRepPrefix) {
                mask = 0x3F;
            } else {
                mask = 0x1F;
            }
            imm = mask & INS_OperandImmediate(ins, OP_1);
        }
        imm++; // HINT: as long as flags are untainted, rcr is just a ror operation with N+1 instead of N rotations

        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_rol_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_rol_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_UINT32, imm,
//                               IARG_UINT32, 1,
//                               IARG_END);
            }
        }
    }
}


static void PIN_FAST_ANALYSIS_CALL r_ror_op(THREADID tid, uint32_t reg_dst, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = RTAG[reg_dst][i];
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            RTAG[reg_dst][i] = dst_tags[i - (byteCount - res.quot)];
        }
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            RTAG[reg_dst][i] = dst_tags[i + res.quot];
        }
    } else { // We need to combine the taint
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[i - (byteCount - res.quot)], dst_tags[i - (byteCount - res.quot) + 1]);
        }
        RTAG[reg_dst][byteCount - res.quot - 1] = tag_combine(dst_tags[byteCount - 1], dst_tags[0]);
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            RTAG[reg_dst][i] = tag_combine(dst_tags[i + res.quot], dst_tags[i + res.quot + 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL r_reg_ror_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;

    r_ror_op(tid, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL m_ror_op(THREADID tid, uint64_t addr, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t dst_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        dst_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            tagmap_setb(addr + i, dst_tags[i - (byteCount - res.quot)]);
        }
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            tagmap_setb(addr + i, dst_tags[i + res.quot]);
        }
    } else { // We need to combine the taint
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            tagmap_setb(addr + i, tag_combine(dst_tags[i - (byteCount - res.quot)], dst_tags[i - (byteCount - res.quot) + 1]));
        }
        tagmap_setb(addr + byteCount - res.quot - 1, tag_combine(dst_tags[byteCount - 1], dst_tags[0]));
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            tagmap_setb(addr + i, tag_combine(dst_tags[i + res.quot], dst_tags[i + res.quot + 1]));
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m_reg_ror_op(THREADID tid, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;

    m_ror_op(tid, addr, imm, byteCount);
}


void ins_ror_op(INS ins) {
    BOOL hasRepPrefix = INS_RepPrefix(ins);
    if (INS_OperandIsReg(ins, OP_1)) {
        REG reg_cnt = INS_OperandReg(ins, OP_1);
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                 // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_ror_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_ror_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_ror_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_UINT32, 1,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        }
    } else {
        uint32_t imm = 1; // If no other immediate or value from RCX are used, then the second operand is 1
        uint32_t mask = 0;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            if (hasRepPrefix) {
                mask = 0x3F;
            } else {
                mask = 0x1F;
            }
            imm = mask & INS_OperandImmediate(ins, OP_1);
        }
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_UINT32, imm,
//                               IARG_UINT32, 1,
//                               IARG_END);
            }
        }
    }
}


static void PIN_FAST_ANALYSIS_CALL r_reg_rcr_op(THREADID tid, uint32_t reg_dst, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;
    imm++;

    r_ror_op(tid, reg_dst, imm, byteCount);
}

static void PIN_FAST_ANALYSIS_CALL m_reg_rcr_op(THREADID tid, uint64_t addr, uint8_t *reg_cnt, uint32_t byteCount, BOOL hasRepPrefix) {
    uint32_t imm = (uint32_t)(*(reg_cnt));
    uint32_t mask = 0;
    if (hasRepPrefix) {
        mask = 0x3F;
    } else {
        mask = 0x1F;
    }
    imm = mask & imm;
    imm++;

    m_ror_op(tid, addr, imm, byteCount);
}


void ins_rcr_op(INS ins) {
    BOOL hasRepPrefix = INS_RepPrefix(ins);
    if (INS_OperandIsReg(ins, OP_1)) {
        REG reg_cnt = INS_OperandReg(ins, OP_1);
        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                 // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcr_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_reg_rcr_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 8,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 4,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcr_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_REG_CONST_REFERENCE, reg_cnt,
                               IARG_UINT32, 2,
                               IARG_BOOL, hasRepPrefix,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_reg_rcr_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_REG_CONST_REFERENCE, reg_cnt,
//                               IARG_UINT32, 1,
//                               IARG_BOOL, hasRepPrefix,
//                               IARG_END);
            }
        }
    } else {
        uint32_t imm = 1; // If no other immediate or value from RCX are used, then the second operand is 1
        uint32_t mask = 0;
        if (INS_OperandIsImmediate(ins, OP_1)) {
            if (hasRepPrefix) {
                mask = 0x3F;
            } else {
                mask = 0x1F;
            }
            imm = mask & INS_OperandImmediate(ins, OP_1);
        }
        imm ++; // HINT: as long as flags are untainted, rcr is just a ror operation with N+1 instead of N rotations

        if (INS_MemoryOperandCount(ins) == 0) {
            REG reg_dst = INS_OperandReg(ins, OP_0);
            if (REG_is_gr64(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (REG_is_gr32(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (REG_is_gr16(reg_dst)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst),
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (REG_is_Lower8(reg_dst)) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op_lower8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
//            } else {
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_ror_op_upper8,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_UINT32, REG_INDX(reg_dst),
//                               IARG_UINT32, imm,
//                               IARG_END);
            }
        } else {
            if (INS_MemoryOperandSize(ins, OP_0) == 8) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 8,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 4,
                               IARG_END);
            } else if (INS_MemoryOperandSize(ins, OP_0) == 2) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_MEMORYWRITE_EA,
                               IARG_UINT32, imm,
                               IARG_UINT32, 2,
                               IARG_END);
//            } else if (INS_MemoryOperandSize(ins, OP_0) == 1) {
//                // HINT: As long as the carry flag is not tainted, this is not needed
//                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m_ror_op,
//                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
//                               IARG_MEMORYWRITE_EA,
//                               IARG_UINT32, imm,
//                               IARG_UINT32, 1,
//                               IARG_END);
            }
        }
    }
}


static void PIN_FAST_ANALYSIS_CALL r2r_rorx_op(THREADID tid, uint32_t reg_dst, uint32_t reg_src, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t src_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = RTAG[reg_src][i];
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            RTAG[reg_dst][i] = src_tags[i - (byteCount - res.quot)];
        }
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            RTAG[reg_dst][i] = src_tags[i + res.quot];
        }
    } else { // We need to combine the taint
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            RTAG[reg_dst][i] = tag_combine(src_tags[i - (byteCount - res.quot)], src_tags[i - (byteCount - res.quot) + 1]);
        }
        RTAG[reg_dst][byteCount - res.quot - 1] = tag_combine(src_tags[byteCount - 1], src_tags[0]);
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            RTAG[reg_dst][i] = tag_combine(src_tags[i + res.quot], src_tags[i + res.quot + 1]);
        }
    }
}

static void PIN_FAST_ANALYSIS_CALL m2r_rorx_op(THREADID tid, uint32_t reg_dst, uint64_t addr, uint32_t imm, uint32_t byteCount) {
    if (imm == 0) {
        return;
    }

    tag_t src_tags[byteCount];
    for (size_t i = 0; i < byteCount; i++) {
        src_tags[i] = MTAG(addr + i);
    }

    // Calculate bytewise taint from bitwise shift
    auto res = std::div(imm, 8);

    // If the bitshift uses whole bytes
    if (res.rem == 0) {
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            tagmap_setb(addr + i, src_tags[i - (byteCount - res.quot)]);
        }
        for (size_t i = byteCount - res.quot - 1; i < byteCount; i--) {
            tagmap_setb(addr + i, src_tags[i + res.quot]);
        }
    } else { // We need to combine the taint
        for (size_t i = byteCount - 1; i >= byteCount - (uint32_t)res.quot; i--) {
            tagmap_setb(addr + i, tag_combine(src_tags[i - (byteCount - res.quot)], src_tags[i - (byteCount - res.quot) + 1]));
        }
        tagmap_setb(addr + byteCount - res.quot - 1, tag_combine(src_tags[byteCount - 1], src_tags[0]));
        for (size_t i = byteCount - res.quot - 2; i < byteCount; i--) {
            tagmap_setb(addr + i, tag_combine(src_tags[i + res.quot], src_tags[i + res.quot + 1]));
        }
    }
}



void ins_rorx_ins(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    uint32_t imm = INS_OperandImmediate(ins, OP_2);
    if (INS_MemoryOperandCount(ins) == 0) {
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_gr64(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_rorx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, 8,
                           IARG_END);
        } else if (REG_is_gr32(reg_dst)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) r2r_rorx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_UINT32, REG_INDX(reg_src),
                           IARG_UINT32, imm,
                           IARG_UINT32, 4,
                           IARG_END);
        }
    } else if (INS_OperandIsMemory(ins, OP_1)) {
        if (INS_MemoryOperandSize(ins, OP_0) == 8) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_rorx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, imm,
                           IARG_UINT32, 8,
                           IARG_END);
        } else if (INS_MemoryOperandSize(ins, OP_0) == 4) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) m2r_rorx_op,
                           IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                           IARG_UINT32, REG_INDX(reg_dst),
                           IARG_MEMORYREAD_EA,
                           IARG_UINT32, imm,
                           IARG_UINT32, 4,
                           IARG_END);
        }
    } else {
        LOG_UNHANDLED_OPCODE(ins);
    }
}



void PIN_FAST_ANALYSIS_CALL r2r_vpbroadcastb_opx(THREADID tid, uint32_t dst, uint32_t src) {
    for (size_t i = 0; i < 16; i++) {
        RTAG[dst][i] = RTAG[src][0];
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_vpbroadcastb_opy(THREADID tid, uint32_t dst, uint32_t src) {
    for (size_t i = 0; i < 32; i++) {
        RTAG[dst][i] = RTAG[src][0];
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_vpbroadcastb_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tag = MTAG(src);

    for (size_t i = 0; i < 16; i++) {
        RTAG[dst][i] = src_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_vpbroadcastb_opy(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tag = MTAG(src);

    for (size_t i = 0; i < 32; i++) {
        RTAG[dst][i] = src_tag;
    }
}

void ins_vpbroadcastb_op(INS ins) {
    REG reg_dst, reg_src;
    if (INS_OperandIsMemory(ins, OP_1)) {
        reg_dst = INS_OperandReg(ins, OP_0);
        if (REG_is_xmm(reg_dst)) {
            R_CALL(m2r_vpbroadcastb_opx, reg_dst);
        } else if (REG_is_ymm(reg_dst)) {
            R_CALL(m2r_vpbroadcastb_opy, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        reg_dst = INS_OperandReg(ins, OP_0);
        reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_vpbroadcastb_opx, reg_dst, reg_src);
        } else if (REG_is_ymm(reg_dst)) {
            R2R_CALL(r2r_vpbroadcastb_opy, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_all_opl(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R32TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 4; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 4; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_all_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R64TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 8; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_all_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R128TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 16; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 16; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_all_opy(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tags[] = R256TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 32; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 32; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_all_opl(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M32TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 4; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 4; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_all_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M64TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 8; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 8; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_all_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M128TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 16; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 16; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_all_opy(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tags[] = M256TAG(src);
    tag_t combined_tag;

    for (size_t i = 0; i < 32; i++) {
        combined_tag = tag_combine(combined_tag, src_tags[i]);
    }

    for (size_t i = 0; i < 32; i++) {
        RTAG[dst][i] = combined_tag;
    }
}

void ins_combine_all_bytes(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (INS_OperandIsMemory(ins, OP_1)) {
        if (REG_is_gr32(reg_dst)) {
            M2R_CALL(m2r_combine_all_opl, reg_dst);
        } else if (REG_is_gr64(reg_dst)) {
            M2R_CALL(m2r_combine_all_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_combine_all_opx, reg_dst);
        } else if (REG_is_ymm(reg_dst)) {
            M2R_CALL(m2r_combine_all_opy, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_gr32(reg_dst)) {
            R2R_CALL(r2r_combine_all_opl, reg_dst, reg_src);
        } else if (REG_is_gr64(reg_dst)) {
            R2R_CALL(r2r_combine_all_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_combine_all_opx, reg_dst, reg_src);
        } else if (REG_is_ymm(reg_dst)) {
            R2R_CALL(r2r_combine_all_opy, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_allinone_opw(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag[] = R16TAG(src);
    tag_t dst_tag[] = R16TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 2; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 2; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 2; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }    
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_allinone_opl(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag[] = R32TAG(src);
    tag_t dst_tag[] = R32TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 4; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 4; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 4; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}    

void PIN_FAST_ANALYSIS_CALL r2r_combine_allinone_opq(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag[] = R64TAG(src);
    tag_t dst_tag[] = R64TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 8; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 8; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 8; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_allinone_opx(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag[] = R128TAG(src);
    tag_t dst_tag[] = R128TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 16; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 16; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 16; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL r2r_combine_allinone_opy(THREADID tid, uint32_t dst, uint32_t src) {
    tag_t src_tag[] = R256TAG(src);
    tag_t dst_tag[] = R256TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 32; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 32; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 32; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_allinone_opw(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tag[] = M16TAG(src);
    tag_t dst_tag[] = R16TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 2; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 2; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 2; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_allinone_opl(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tag[] = M32TAG(src);
    tag_t dst_tag[] = R32TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 4; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 4; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 4; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_allinone_opq(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tag[] = M64TAG(src);
    tag_t dst_tag[] = R64TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 8; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 8; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 8; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_allinone_opx(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tag[] = M128TAG(src);
    tag_t dst_tag[] = R128TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 16; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 16; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 16; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void PIN_FAST_ANALYSIS_CALL m2r_combine_allinone_opy(THREADID tid, uint32_t dst, ADDRINT src) {
    tag_t src_tag[] = M256TAG(src);
    tag_t dst_tag[] = R256TAG(dst);

    tag_t combined_src_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 32; ++i) {
        combined_src_tag = tag_combine(combined_src_tag, src_tag[i]);
    }

    tag_t combined_dst_tag = tag_traits<tag_t>::cleared_val;
    for (size_t i = 0; i < 32; ++i) {
        combined_dst_tag = tag_combine(combined_dst_tag, dst_tag[i]);
    }

    for (size_t i = 0; i < 32; ++i) {
        RTAG[dst][i] = tag_combine(combined_src_tag, combined_dst_tag);
    }
}

void ins_combine_all_bytes_in_dst(INS ins) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (INS_OperandIsMemory(ins, OP_1)) {
        if (REG_is_gr16(reg_dst)) {
            M2R_CALL(m2r_combine_allinone_opl, reg_dst);
        } else if (REG_is_gr32(reg_dst)) {
            M2R_CALL(m2r_combine_allinone_opl, reg_dst);
        } else if (REG_is_gr64(reg_dst)) {
            M2R_CALL(m2r_combine_allinone_opq, reg_dst);
        } else if (REG_is_xmm(reg_dst)) {
            M2R_CALL(m2r_combine_allinone_opx, reg_dst);
        } else if (REG_is_ymm(reg_dst)) {
            M2R_CALL(m2r_combine_allinone_opy, reg_dst);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    } else {
        REG reg_src = INS_OperandReg(ins, OP_1);
        if (REG_is_gr16(reg_dst)) {
            R2R_CALL(r2r_combine_allinone_opw, reg_dst, reg_src);
        } else if (REG_is_gr32(reg_dst)) {
            R2R_CALL(r2r_combine_allinone_opl, reg_dst, reg_src);
        } else if (REG_is_gr64(reg_dst)) {
            R2R_CALL(r2r_combine_allinone_opq, reg_dst, reg_src);
        } else if (REG_is_xmm(reg_dst)) {
            R2R_CALL(r2r_combine_allinone_opx, reg_dst, reg_src);
        } else if (REG_is_ymm(reg_dst)) {
            R2R_CALL(r2r_combine_allinone_opy, reg_dst, reg_src);
        } else {
            LOG_UNHANDLED_OPCODE(ins);
        }
    }
}