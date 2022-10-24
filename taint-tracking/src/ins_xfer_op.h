#ifndef __INS_XFER_OP_H__
#define __INS_XFER_OP_H__
#include "pin.H"

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy(THREADID tid, uint32_t dst, uint32_t src);

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u(THREADID tid, uint32_t dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l(THREADID tid, uint32_t dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(THREADID tid, uint32_t dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(THREADID tid, uint32_t dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq(THREADID tid, uint32_t dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx(THREADID tid, uint32_t dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy(THREADID tid, uint32_t dst, ADDRINT src);

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u(THREADID tid, ADDRINT dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l(THREADID tid, ADDRINT dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(THREADID tid, ADDRINT dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(THREADID tid, ADDRINT dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq(THREADID tid, ADDRINT dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx(THREADID tid, ADDRINT dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy(THREADID tid, ADDRINT dst, uint32_t src);

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src);
void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq(ADDRINT dst, ADDRINT src);

void ins_xfer_op(INS ins);
void ins_xfer_op_predicated(INS ins);

void ins_push_op(INS ins);
void ins_pop_op(INS ins);

void ins_stosb(INS ins);
void ins_stosw(INS ins);
void ins_stosd(INS ins);
void ins_stosq(INS ins);

void ins_movlp(INS ins);
void ins_movhp(INS ins);

void ins_lea(INS ins);
void ins_movbe_op(INS ins);

void ins_punpcklbw_op(INS ins);
void ins_punpcklwd_op(INS ins);
void ins_punpckldq_op(INS ins);
void ins_punpcklqdq_op(INS ins);
void ins_punpckhbw_op(INS ins);
void ins_punpckhwd_op(INS ins);
void ins_punpckhdq_op(INS ins);
void ins_punpckhqdq_op(INS ins);
void ins_vpunpckhqdq_op(INS ins);

void ins_pshufd_op(INS ins);
void ins_vpshufd_op(INS ins);
void ins_pslldq_op(INS ins);
void ins_psrldq_op(INS ins);

void ins_vpslldq_op(INS ins);
void ins_vpsrldq_op(INS ins);

void ins_psllx_op(INS ins, uint32_t chunkSize);
void ins_vpsllx_op(INS ins, uint32_t chunkSize);
void ins_psrlx_op(INS ins, uint32_t chunkSize);
void ins_vpsrlx_op(INS ins, uint32_t chunkSize);

void ins_shld_op(INS ins);
void ins_shrd_op(INS ins);
void ins_rol_op(INS ins);
void ins_rcl_op(INS ins);
void ins_ror_op(INS ins);
void ins_rorx_ins(INS ins);
void ins_rcr_op(INS ins);
void ins_shl_op(INS ins);
void ins_shr_op(INS ins);

void ins_vpbroadcastb_op(INS ins);

// These are totally overtainting and should only be used for debugging!
void ins_combine_all_bytes(INS ins);
void ins_combine_all_bytes_in_dst(INS ins);

#endif