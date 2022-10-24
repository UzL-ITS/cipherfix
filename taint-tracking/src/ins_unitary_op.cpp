#include "ins_unitary_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_u(THREADID tid,
                                                     uint32_t src) {
  tag_t tmp_tag = RTAG[src][1];

  RTAG[DFT_REG_RAX][0] = tag_combine(RTAG[DFT_REG_RAX][0], tmp_tag);
  RTAG[DFT_REG_RAX][1] = tag_combine(RTAG[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_l(THREADID tid,
                                                     uint32_t src) {
  tag_t tmp_tag = RTAG[src][0];

  RTAG[DFT_REG_RAX][0] = tag_combine(RTAG[DFT_REG_RAX][0], tmp_tag);
  RTAG[DFT_REG_RAX][1] = tag_combine(RTAG[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opw(THREADID tid, uint32_t src) {
  tag_t tmp_tag[] = {RTAG[src][0], RTAG[src][1]};
  tag_t dst2_tag[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1]};

  tag_t combined_src1_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 2; ++i) {
    combined_src1_tag = tag_combine(combined_src1_tag, tmp_tag[i]);
  }

  tag_t combined_src2_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 2; ++i) {
    combined_src2_tag = tag_combine(combined_src2_tag, dst2_tag[i]);
  }

  for (size_t i = 0; i < 2; ++i) {
    RTAG[DFT_REG_RAX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
    RTAG[DFT_REG_RDX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opq(THREADID tid, uint32_t src) {
  tag_t tmp_tag[] = R64TAG(src);
  tag_t dst2_tag[] = R64TAG(DFT_REG_RAX);

  tag_t combined_src1_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 8; ++i) {
    combined_src1_tag = tag_combine(combined_src1_tag, tmp_tag[i]);
  }

  tag_t combined_src2_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 8; ++i) {
    combined_src2_tag = tag_combine(combined_src2_tag, dst2_tag[i]);
  }

  for (size_t i = 0; i < 8; ++i) {
    RTAG[DFT_REG_RAX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
    RTAG[DFT_REG_RDX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opl(THREADID tid, uint32_t src) {
  tag_t tmp_tag[] = R32TAG(src);
  tag_t dst2_tag[] = R32TAG(DFT_REG_RAX);

  tag_t combined_src1_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 4; ++i) {
    combined_src1_tag = tag_combine(combined_src1_tag, tmp_tag[i]);
  }

  tag_t combined_src2_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 4; ++i) {
    combined_src2_tag = tag_combine(combined_src2_tag, dst2_tag[i]);
  }

  for (size_t i = 0; i < 4; ++i) {
    RTAG[DFT_REG_RAX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
    RTAG[DFT_REG_RDX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opb(THREADID tid, ADDRINT src) {
  tag_t tmp_tag = MTAG(src);
  tag_t dst_tag[] = R16TAG(DFT_REG_RAX);

  RTAG[DFT_REG_RAX][0] = tag_combine(dst_tag[0], tmp_tag);
  RTAG[DFT_REG_RAX][1] = tag_combine(dst_tag[1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opw(THREADID tid, ADDRINT src) {
  tag_t tmp_tag[] = M16TAG(src);
  tag_t dst2_tag[] = R16TAG(DFT_REG_RAX);

  tag_t combined_src1_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 2; ++i) {
    combined_src1_tag = tag_combine(combined_src1_tag, tmp_tag[i]);
  }

  tag_t combined_src2_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 2; ++i) {
    combined_src2_tag = tag_combine(combined_src2_tag, dst2_tag[i]);
  }

  for (size_t i = 0; i < 2; ++i) {
    RTAG[DFT_REG_RAX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
    RTAG[DFT_REG_RDX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opq(THREADID tid, ADDRINT src) {
  tag_t tmp_tag[] = M64TAG(src);
  tag_t dst2_tag[] = R64TAG(DFT_REG_RAX);

  tag_t combined_src1_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 8; ++i) {
    combined_src1_tag = tag_combine(combined_src1_tag, tmp_tag[i]);
  }

  tag_t combined_src2_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 8; ++i) {
    combined_src2_tag = tag_combine(combined_src2_tag, dst2_tag[i]);
  }

  for (size_t i = 0; i < 8; ++i) {
    RTAG[DFT_REG_RAX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
    RTAG[DFT_REG_RDX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opl(THREADID tid, ADDRINT src) {
  tag_t tmp_tag[] = M32TAG(src);
  tag_t dst2_tag[] = R32TAG(DFT_REG_RAX);

  tag_t combined_src1_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 4; ++i) {
    combined_src1_tag = tag_combine(combined_src1_tag, tmp_tag[i]);
  }

  tag_t combined_src2_tag = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < 4; ++i) {
    combined_src2_tag = tag_combine(combined_src2_tag, dst2_tag[i]);
  }

  for (size_t i = 0; i < 4; ++i) {
    RTAG[DFT_REG_RAX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
    RTAG[DFT_REG_RDX][i] = tag_combine(combined_src1_tag, combined_src2_tag);
  }
}

void ins_unitary_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0))
    switch (INS_MemoryOperandSize(ins, OP_0)) {
    case BIT2BYTE(MEM_64BIT_LEN):
      M_CALL_R(m2r_unitary_opq);
      break;
    case BIT2BYTE(MEM_LONG_LEN):
      M_CALL_R(m2r_unitary_opl);
      break;
    case BIT2BYTE(MEM_WORD_LEN):
      M_CALL_R(m2r_unitary_opw);
      break;
    case BIT2BYTE(MEM_BYTE_LEN):
    default:
      M_CALL_R(m2r_unitary_opb);
      break;
    }
  else {
    REG reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src))
      R_CALL(r2r_unitary_opq, reg_src);
    else if (REG_is_gr32(reg_src))
      R_CALL(r2r_unitary_opl, reg_src);
    else if (REG_is_gr16(reg_src))
      R_CALL(r2r_unitary_opw, reg_src);
    else if (REG_is_Upper8(reg_src))
      R_CALL(r2r_unitary_opb_u, reg_src);
    else
      R_CALL(r2r_unitary_opb_l, reg_src);
  }
}

static void PIN_FAST_ANALYSIS_CALL _bswap_opl(THREADID tid, uint32_t reg) {
    tag_t save_tags[] = R32TAG(reg);

    for (size_t i = 0; i < 4; i++) {
        RTAG[reg][3 - i] = save_tags[i];
    }
}

static void PIN_FAST_ANALYSIS_CALL _bswap_opp(THREADID tid, uint32_t reg) {
    tag_t save_tags[] = R64TAG(reg);

    for (size_t i = 0; i < 8; i++) {
        RTAG[reg][7 - i] = save_tags[i];
    }
}

void ins_bswap_op(INS ins) {
    REG reg = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg)) {
        R_CALL(_bswap_opp, reg);
    } else if (REG_is_gr32(reg)) {
        R_CALL(_bswap_opl, reg);
    } else {
        xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
        LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");
    }
}
