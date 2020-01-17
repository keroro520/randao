#include "ckb_syscalls.h"
#include "protocol.h"
#include "common.h"

// TODO * remove the requirement of same phases of inputs/outputs
// TODO * time lock checking
// TODO * verify phase transfer
// TODO MolReader_Verify 里应该会校验长度，其实没必要在前面还检查一次 if len == xxx
// TODO 对于 challenge ，要加上对 capacity 的检查
// TODO 搞懂 "static" 关键字的用处
// TODO 什么时候用 CKB_SOURCE_INPUT 什么时候用 CKB_SOURCE_GROUP_INPUT
// TODO 验证 input 的时候，其实只需要验证 layout，不需要验证 content，所以直接调 verify_xxx 来验证 input 有点浪费

#define ERROR_INVALID_PHASE               -100
#define ERROR_INVALID_CAMPAIGN_ID         -101
#define ERROR_INVALID_CAPACITY            -102
#define ERROR_INVALID_COMMITMENT          -103
#define ERROR_INVALID_REVEAL              -104
#define ERROR_INVALID_AGGREGATE_UNREVEAL  -105
#define ERROR_INVALID_AGGREGATE_REVEAL    -106
#define ERROR_INVALID_AGGREGATE_INPUT     -107

#define SCRIPT_SIZE       32768 /* 32 KB */
#define WITNESS_SIZE      32768 /* 32 KB */
#define OUT_POINT_SIZE    36
#define HASH_SIZE         32
#define SUMMARY_SIZE      32768 /* 32 KB */

#define START_PHASE       1
#define COMMIT_PHASE      2
#define REVEAL_PHASE      3
#define AGGREGATE_PHASE   4
#define FINALIZE_PHASE    5

#define CAMPAIGN_PRE_OCCUPIED 8

struct {
  uint8_t* id;          // OutPoint
  uint64_t deposit;
  uint64_t period;
  uint8_t* script_hash;
} campaign;

mol_seg_res_t load_current_script() {
  mol_seg_res_t script_seg_res;
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_seg_res.errno = ret;
  } else if (len > SCRIPT_SIZE) {
    script_seg_res.errno = ERROR_SCRIPT_TOO_LONG;
  } else {
    script_seg_res.seg.ptr = (uint8_t *)script;
    script_seg_res.seg.size = len;

    if (MolReader_Script_verify(&script_seg_res.seg, false) != MOL_OK) {
      script_seg_res.errno = ERROR_ENCODING;
    } else {
      script_seg_res.errno = MOL_OK;
    }
  }
  return script_seg_res;
}

mol_seg_res_t load_current_script_hash() {
  mol_seg_res_t script_hash_seg_res;
  mol_seg_t script_hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;
  int ret = ckb_load_script_hash(script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_hash_seg_res.errno = ret;
  } else if (len != HASH_SIZE) {
    script_hash_seg_res.errno = ERROR_SYSCALL;
  } else {
    script_hash_seg_res.errno = MOL_OK;
    script_hash_seg_res.seg.ptr = (uint8_t *)script_hash;
    script_hash_seg_res.seg.size = len;
  }
  return script_hash_seg_res;
}

int extract_campaign_info(
  bool* is_campaign_cell, uint8_t* phase, size_t index, size_t source
) {
    int ret;
    unsigned char actual_script_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;

    // Check if this is a campaign cell
    ret = ckb_load_cell_by_field(
        actual_script_hash, &len, 0, index,
        source, CKB_CELL_FIELD_TYPE_HASH
    );
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != HASH_SIZE) {
      return ERROR_SYSCALL;
    }
    if (memcmp(actual_script_hash, campaign.script_hash, HASH_SIZE) != 0) {
      *is_campaign_cell = false;
      return CKB_SUCCESS;
    }

    // Get phase
    len = 8;
    ret = ckb_load_cell_data(
        (unsigned char *)phase, &len, 0, index, source
    );
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != 8) {
      return ERROR_ENCODING;
    }
    if (*phase <= START_PHASE || FINALIZE_PHASE < *phase) {
      return ERROR_INVALID_PHASE;
    }

    // Now we know this cell is campaign cell,
    // and we alreaady get the `phase` and `capacity`.
    *is_campaign_cell = true;
    return CKB_SUCCESS;
}

int initialize() {
  // Load current script
  mol_seg_res_t script_seg_res = load_current_script();
  if (script_seg_res.errno != MOL_OK) {
    return script_seg_res.errno;
  }

  // Load current script hash
  mol_seg_res_t script_hash_seg_res = load_current_script_hash();
  if (script_hash_seg_res.errno != MOL_OK) {
    return script_hash_seg_res.errno;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg_res.seg);
  mol_seg_t campaign_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (MolReader_CampaignArgs_verify(&campaign_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  campaign.id = (uint8_t*)(MolReader_CampaignArgs_get_id(&campaign_seg).ptr);
  campaign.period = *(uint64_t*)(MolReader_CampaignArgs_get_period(&campaign_seg).ptr);
  campaign.deposit = *(uint64_t*)(MolReader_CampaignArgs_get_deposit(&campaign_seg).ptr);
  campaign.script_hash = (uint8_t*)(script_hash_seg_res.seg.ptr);
  return CKB_SUCCESS;
}

int verify_campaign_id(size_t index, size_t source) {
  uint8_t out_point[OUT_POINT_SIZE];
  uint64_t len = OUT_POINT_SIZE;
  int ret = ckb_load_input_by_field(
      out_point, &len, 0, index, source,
      CKB_INPUT_FIELD_OUT_POINT
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != OUT_POINT_SIZE) {
    return ERROR_SYSCALL;
  }

  mol_seg_t out_point_seg;
  out_point_seg.ptr = out_point;
  out_point_seg.size = OUT_POINT_SIZE;
  if (MolReader_OutPoint_verify(&out_point_seg, false) != MOL_OK) {
    return ERROR_SYSCALL;
  }

  if (memcmp(out_point, campaign.id, OUT_POINT_SIZE) != 0) {
    return ERROR_INVALID_CAMPAIGN_ID;
  }
  return MOL_OK;
}

int verify_capacity(uint64_t expected_capacity, size_t index) {
  uint64_t capacity = 0;
  uint64_t len = 8;
  int ret = ckb_load_cell_by_field(
      (unsigned char *)&capacity, &len, 0, index,
      CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != 8) {
    return ERROR_SYSCALL;
  }

  if (capacity != expected_capacity) {
    return ERROR_INVALID_CAPACITY;
  }
  return CKB_SUCCESS;
}

int verify_commitment(size_t index, size_t source) {
  uint64_t len = HASH_SIZE;
  unsigned char commitment[HASH_SIZE];
  int ret = ckb_load_cell_data(
      commitment, &len, CAMPAIGN_PRE_OCCUPIED,
      index, source
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != HASH_SIZE) {
    return ERROR_INVALID_COMMITMENT;
  }

  mol_seg_t commitment_seg;
  commitment_seg.ptr = commitment;
  commitment_seg.size = HASH_SIZE;
  if (MolReader_Byte32_verify(&commitment_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  return CKB_SUCCESS;
}

int verify_reveal_witness(size_t index) {
  unsigned char witness[WITNESS_SIZE];
  uint64_t len = 0;
  int ret = ckb_load_witness(
      witness, &len, 0, index,
      CKB_SOURCE_GROUP_INPUT
  );
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;
  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_SYSCALL;
  }

  mol_seg_t reveal_seg = MolReader_WitnessArgs_get_output_type(&witness_seg);
  if (reveal_seg.size != 8) {
    return ERROR_INVALID_REVEAL;
  }
  return CKB_SUCCESS;
}

int verify_summary(size_t index, size_t source) {
  unsigned char summary[SUMMARY_SIZE];
  uint64_t len = 0;
  int ret = ckb_load_cell_data(summary, &len, CAMPAIGN_PRE_OCCUPIED, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  mol_seg_t summary_seg;
  summary_seg.ptr = (uint8_t *)summary;
  summary_seg.size = len;
  if (MolReader_Summary_verify(&summary_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t unreveals_seg = molreader_summary_get_unreveals(&summary_seg);
  for (mol_num_t i = 0, n = molreader_indexvec_length(&unreveals_seg); i < n; i++) {
    mol_num_t position = *(mol_num_t*)(MolReader_IndexVec_get(&unreveals_seg, i).seg.ptr);
    bool is_campaign_cell;
    uint8_t phase;
    int ret = extract_campaign_info(
        &is_campaign_cell, &phase,
        position, CKB_SOURCE_CELL_DEP
    );
    if (!(ret == CKB_SUCCESS && is_campaign_cell && phase == COMMIT_PHASE)) {
      return ERROR_INVALID_AGGREGATE_REVEAL;
    }
  }

  mol_seg_t reveals_seg = molreader_summary_get_reveals(&summary_seg);
  for (mol_num_t i = 0, n = molreader_indexvec_length(&reveals_seg); i < n; i++) {
    mol_num_t position = *(mol_num_t*)(MolReader_IndexVec_get(&reveals_seg, i).seg.ptr);
    bool is_campaign_cell;
    uint8_t phase;
    int ret = extract_campaign_info(
        &is_campaign_cell, &phase,
        position, CKB_SOURCE_CELL_DEP
    );
    if (!(ret == CKB_SUCCESS && is_campaign_cell && phase == REVEAL_PHASE)) {
      return ERROR_INVALID_AGGREGATE_REVEAL;
    }
  }

  return CKB_SUCCESS;
}

int verify_start(size_t index, size_t source) {
  int ret = verify_capacity(campaign.deposit, index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  return verify_campaign_id(index, source);
}

int verify_commit(size_t index, size_t source) {
  int ret;
  ret = verify_commitment(index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  return verify_capacity(campaign.deposit, index);
}

int verify_reveal(size_t index) {
  int ret = verify_capacity(campaign.deposit, index);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  // TODO verify commitment == hash(reveal)
  return verify_reveal_witness(index);
}

int verify_aggregate(size_t index, size_t source) {
  return verify_summary(index, source);
}

int verify_challenge(size_t index) {
  int ret = verify_summary(index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  uint64_t input_data_size = 0;
  uint64_t output_data_size = 0;
  int ret1 = ckb_load_cell_data(NULL, &input_data_size, 0, index, CKB_SOURCE_INPUT);
  int ret2 = ckb_load_cell_data(NULL, &output_data_size, 0, index, CKB_SOURCE_OUTPUT);
  if (!(ret1 == CKB_SUCCESS && ret2 == CKB_SUCCESS && input_data_size < output_data_size)) {
    return ERROR_INVALID_CHALLENGE;
  }
  return CKB_SUCCESS;
}

int verify_finalize(size_t index) {
  // TODO
  return CKB_SUCCESS;
}

int main() {
  int ret = initialize();
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  for (size_t index = 0; ret == CKB_SUCCESS; index++) {
    bool is_campaign_cell;
    uint8_t phase;
    int ret = extract_campaign_info(
        &is_campaign_cell, &phase,
        index, CKB_SOURCE_OUTPUT
    );
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret != CKB_SUCCESS) {
      return ret;
    } else if (!is_campaign_cell) {
      continue;
    }

    switch (phase) {
      case START_PHASE:
        ret = verify_start(index, CKB_SOURCE_OUTPUT);
      case COMMIT_PHASE:
        ret = verify_commit(index, CKB_SOURCE_OUTPUT);
      case REVEAL_PHASE:
        ret = verify_commit(index, CKB_SOURCE_INPUT);
        if (ret == CKB_SUCCESS) {
          ret = verify_reveal(index);
        }
      case AGGREGATE_PHASE:
        bool input_is_campaign_cell;
        uint8_t input_phase;
        ret = extract_campaign_info(
            &input_is_campaign_cell, &input_phase,
            index, CKB_SOURCE_INPUT
        );
        if (ret != CKB_SUCCESS) {
          return ret;
        }
        if (!input_is_campaign_cell) {
          return ERROR_INVALID_AGGREGATE_INPUT;
        }
        if (phase == START_PHASE) {
          // Normal
          //
          // As for normal AggregateCell, we expect its capacity be equal to
          // StartCell.capacity + campaign.deposit, which can be simplify to
          // 2 * campaign.deposit
          ret = verify_capacity(2 * campaign.deposit, index);
          if (ret == CKB_SUCCESS) {
            ret = verify_start(index, CKB_SOURCE_INPUT);
            if (ret == CKB_SUCCESS) {
              ret = verify_aggregate(index, CKB_SOURCE_OUTPUT);
            }
          }
        } else if (phase == AGGREGATE_PHASE) {
          // Challenge
          // TODO verify capacity
          ret = verify_aggregate(index, CKB_SOURCE_INPUT);
          if (ret == CKB_SUCCESS) {
            ret = verify_challenge(index, CKB_SOURCE_OUTPUT);
          }
        } else {
          return ERROR_INVALID_AGGREGATE_INPUT;
        }
      case FINALIZE_PHASE:
        ret = verify_aggregate(index, CKB_SOURCE_INPUT);
        if (ret == CKB_SUCCESS) {
          ret = verify_finalize(index);
        }
    }
  }

  return ret;
}
