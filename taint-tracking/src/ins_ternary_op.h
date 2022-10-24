
#ifndef __INS_TERNARY_OP_H__
#define __INS_TERNARY_OP_H__
#include "pin.H"

void ins_ternary_op(INS ins);
void ins_clear_ternary_op(INS ins);

void ins_pminub_op(INS ins);

void ins_vpminub_op(INS ins);

void ins_pmovmskb_op(INS ins);

void ins_pinsrd_op(INS ins);

void ins_vinserti_op(INS ins);

void ins_sarx_op(INS ins);

#endif