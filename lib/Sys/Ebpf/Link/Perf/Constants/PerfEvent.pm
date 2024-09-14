package Sys::Ebpf::Link::Perf::Constants::PerfEvent;

use strict;
use warnings;
use utf8;

use Exporter 'import';

# cf. https://github.com/torvalds/linux/blob/master/include/uapi/linux/perf_event.h
my %constants = (

    # enum: perf_type_id
    'PERF_TYPE_HARDWARE'   => 0,
    'PERF_TYPE_SOFTWARE'   => 1,
    'PERF_TYPE_TRACEPOINT' => 2,
    'PERF_TYPE_HW_CACHE'   => 3,
    'PERF_TYPE_RAW'        => 4,
    'PERF_TYPE_BREAKPOINT' => 5,
    'PERF_TYPE_MAX'        => 6,    # non-ABI

    # enum: perf_hw_id
    'PERF_COUNT_HW_CPU_CYCLES'              => 0,
    'PERF_COUNT_HW_INSTRUCTIONS'            => 1,
    'PERF_COUNT_HW_CACHE_REFERENCES'        => 2,
    'PERF_COUNT_HW_CACHE_MISSES'            => 3,
    'PERF_COUNT_HW_BRANCH_INSTRUCTIONS'     => 4,
    'PERF_COUNT_HW_BRANCH_MISSES'           => 5,
    'PERF_COUNT_HW_BUS_CYCLES'              => 6,
    'PERF_COUNT_HW_STALLED_CYCLES_FRONTEND' => 7,
    'PERF_COUNT_HW_STALLED_CYCLES_BACKEND'  => 8,
    'PERF_COUNT_HW_REF_CPU_CYCLES'          => 9,
    'PERF_COUNT_HW_MAX'                     => 10,    # non-ABI

    # enum: perf_hw_cache_id
    'PERF_COUNT_HW_CACHE_L1D'  => 0,
    'PERF_COUNT_HW_CACHE_L1I'  => 1,
    'PERF_COUNT_HW_CACHE_LL'   => 2,
    'PERF_COUNT_HW_CACHE_DTLB' => 3,
    'PERF_COUNT_HW_CACHE_ITLB' => 4,
    'PERF_COUNT_HW_CACHE_BPU'  => 5,
    'PERF_COUNT_HW_CACHE_NODE' => 6,
    'PERF_COUNT_HW_CACHE_MAX'  => 7,                  # non-ABI

    # enum: perf_hw_cache_op_id
    'PERF_COUNT_HW_CACHE_OP_READ'     => 0,
    'PERF_COUNT_HW_CACHE_OP_WRITE'    => 1,
    'PERF_COUNT_HW_CACHE_OP_PREFETCH' => 2,
    'PERF_COUNT_HW_CACHE_OP_MAX'      => 3,           # non-ABI

    # enum: perf_hw_cache_op_result_id
    'PERF_COUNT_HW_CACHE_RESULT_ACCESS' => 0,
    'PERF_COUNT_HW_CACHE_RESULT_MISS'   => 1,
    'PERF_COUNT_HW_CACHE_RESULT_MAX'    => 2,         # non-ABI

    # enum: perf_sw_ids
    'PERF_COUNT_SW_CPU_CLOCK'        => 0,
    'PERF_COUNT_SW_TASK_CLOCK'       => 1,
    'PERF_COUNT_SW_PAGE_FAULTS'      => 2,
    'PERF_COUNT_SW_CONTEXT_SWITCHES' => 3,
    'PERF_COUNT_SW_CPU_MIGRATIONS'   => 4,
    'PERF_COUNT_SW_PAGE_FAULTS_MIN'  => 5,
    'PERF_COUNT_SW_PAGE_FAULTS_MAJ'  => 6,
    'PERF_COUNT_SW_ALIGNMENT_FAULTS' => 7,
    'PERF_COUNT_SW_EMULATION_FAULTS' => 8,
    'PERF_COUNT_SW_DUMMY'            => 9,
    'PERF_COUNT_SW_BPF_OUTPUT'       => 10,
    'PERF_COUNT_SW_CGROUP_SWITCHES'  => 11,
    'PERF_COUNT_SW_MAX'              => 12,    # non-ABI

    # enum: perf_event_sample_format
    'PERF_SAMPLE_IP'             => 1 << 0,
    'PERF_SAMPLE_TID'            => 1 << 1,
    'PERF_SAMPLE_TIME'           => 1 << 2,
    'PERF_SAMPLE_ADDR'           => 1 << 3,
    'PERF_SAMPLE_READ'           => 1 << 4,
    'PERF_SAMPLE_CALLCHAIN'      => 1 << 5,
    'PERF_SAMPLE_ID'             => 1 << 6,
    'PERF_SAMPLE_CPU'            => 1 << 7,
    'PERF_SAMPLE_PERIOD'         => 1 << 8,
    'PERF_SAMPLE_STREAM_ID'      => 1 << 9,
    'PERF_SAMPLE_RAW'            => 1 << 10,
    'PERF_SAMPLE_BRANCH_STACK'   => 1 << 11,
    'PERF_SAMPLE_REGS_USER'      => 1 << 12,
    'PERF_SAMPLE_STACK_USER'     => 1 << 13,
    'PERF_SAMPLE_WEIGHT'         => 1 << 14,
    'PERF_SAMPLE_DATA_SRC'       => 1 << 15,
    'PERF_SAMPLE_IDENTIFIER'     => 1 << 16,
    'PERF_SAMPLE_TRANSACTION'    => 1 << 17,
    'PERF_SAMPLE_REGS_INTR'      => 1 << 18,
    'PERF_SAMPLE_PHYS_ADDR'      => 1 << 19,
    'PERF_SAMPLE_AUX'            => 1 << 20,
    'PERF_SAMPLE_CGROUP'         => 1 << 21,
    'PERF_SAMPLE_DATA_PAGE_SIZE' => 1 << 22,
    'PERF_SAMPLE_CODE_PAGE_SIZE' => 1 << 23,
    'PERF_SAMPLE_WEIGHT_STRUCT'  => 1 << 24,
    'PERF_SAMPLE_WEIGHT_TYPE'    => ( 1 << 14 ) | ( 1 << 24 ),
    'PERF_SAMPLE_MAX'            => 1 << 25,                     # non-ABI

    # enum: perf_branch_sample_type_shift
    'PERF_SAMPLE_BRANCH_USER_SHIFT'       => 0,
    'PERF_SAMPLE_BRANCH_KERNEL_SHIFT'     => 1,
    'PERF_SAMPLE_BRANCH_HV_SHIFT'         => 2,
    'PERF_SAMPLE_BRANCH_ANY_SHIFT'        => 3,
    'PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT'   => 4,
    'PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT' => 5,
    'PERF_SAMPLE_BRANCH_IND_CALL_SHIFT'   => 6,
    'PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT'   => 7,
    'PERF_SAMPLE_BRANCH_IN_TX_SHIFT'      => 8,
    'PERF_SAMPLE_BRANCH_NO_TX_SHIFT'      => 9,
    'PERF_SAMPLE_BRANCH_COND_SHIFT'       => 10,
    'PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT' => 11,
    'PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT'   => 12,
    'PERF_SAMPLE_BRANCH_CALL_SHIFT'       => 13,
    'PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT'   => 14,
    'PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT'  => 15,
    'PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT'  => 16,
    'PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT'   => 17,
    'PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT'  => 18,
    'PERF_SAMPLE_BRANCH_COUNTERS_SHIFT'   => 19,
    'PERF_SAMPLE_BRANCH_MAX_SHIFT'        => 20,    # non-ABI

    # enum: perf_branch_sample_type
    'PERF_SAMPLE_BRANCH_USER'       => 1 << 0,
    'PERF_SAMPLE_BRANCH_KERNEL'     => 1 << 1,
    'PERF_SAMPLE_BRANCH_HV'         => 1 << 2,
    'PERF_SAMPLE_BRANCH_ANY'        => 1 << 3,
    'PERF_SAMPLE_BRANCH_ANY_CALL'   => 1 << 4,
    'PERF_SAMPLE_BRANCH_ANY_RETURN' => 1 << 5,
    'PERF_SAMPLE_BRANCH_IND_CALL'   => 1 << 6,
    'PERF_SAMPLE_BRANCH_ABORT_TX'   => 1 << 7,
    'PERF_SAMPLE_BRANCH_IN_TX'      => 1 << 8,
    'PERF_SAMPLE_BRANCH_NO_TX'      => 1 << 9,
    'PERF_SAMPLE_BRANCH_COND'       => 1 << 10,
    'PERF_SAMPLE_BRANCH_CALL_STACK' => 1 << 11,
    'PERF_SAMPLE_BRANCH_IND_JUMP'   => 1 << 12,
    'PERF_SAMPLE_BRANCH_CALL'       => 1 << 13,
    'PERF_SAMPLE_BRANCH_NO_FLAGS'   => 1 << 14,
    'PERF_SAMPLE_BRANCH_NO_CYCLES'  => 1 << 15,
    'PERF_SAMPLE_BRANCH_TYPE_SAVE'  => 1 << 16,
    'PERF_SAMPLE_BRANCH_HW_INDEX'   => 1 << 17,
    'PERF_SAMPLE_BRANCH_PRIV_SAVE'  => 1 << 18,
    'PERF_SAMPLE_BRANCH_COUNTERS'   => 1 << 19,
    'PERF_SAMPLE_BRANCH_MAX'        => 1 << 20,

    # enum: Branch Types
    'PERF_BR_UNKNOWN'    => 0,
    'PERF_BR_COND'       => 1,
    'PERF_BR_UNCOND'     => 2,
    'PERF_BR_IND'        => 3,
    'PERF_BR_CALL'       => 4,
    'PERF_BR_IND_CALL'   => 5,
    'PERF_BR_RET'        => 6,
    'PERF_BR_SYSCALL'    => 7,
    'PERF_BR_SYSRET'     => 8,
    'PERF_BR_COND_CALL'  => 9,
    'PERF_BR_COND_RET'   => 10,
    'PERF_BR_ERET'       => 11,
    'PERF_BR_IRQ'        => 12,
    'PERF_BR_SERROR'     => 13,
    'PERF_BR_NO_TX'      => 14,
    'PERF_BR_EXTEND_ABI' => 15,
    'PERF_BR_MAX'        => 16,    # non-ABI

    # enum: Branch Speculation Outcome
    'PERF_BR_SPEC_NA'               => 0,
    'PERF_BR_SPEC_WRONG_PATH'       => 1,
    'PERF_BR_NON_SPEC_CORRECT_PATH' => 2,
    'PERF_BR_SPEC_CORRECT_PATH'     => 3,
    'PERF_BR_SPEC_MAX'              => 4,    # non-ABI

    # enum: Branch New Fault Types
    'PERF_BR_NEW_FAULT_ALGN' => 0,
    'PERF_BR_NEW_FAULT_DATA' => 1,
    'PERF_BR_NEW_FAULT_INST' => 2,
    'PERF_BR_NEW_ARCH_1'     => 3,
    'PERF_BR_NEW_ARCH_2'     => 4,
    'PERF_BR_NEW_ARCH_3'     => 5,
    'PERF_BR_NEW_ARCH_4'     => 6,
    'PERF_BR_NEW_ARCH_5'     => 7,
    'PERF_BR_NEW_MAX'        => 8,           # non-ABI

    # enum: Branch Privilege Levels
    'PERF_BR_PRIV_UNKNOWN' => 0,
    'PERF_BR_PRIV_USER'    => 1,
    'PERF_BR_PRIV_KERNEL'  => 2,
    'PERF_BR_PRIV_HV'      => 3,

    # enum: perf_sample_regs_abi
    'PERF_SAMPLE_REGS_ABI_NONE' => 0,
    'PERF_SAMPLE_REGS_ABI_32'   => 1,
    'PERF_SAMPLE_REGS_ABI_64'   => 2,

    # enum: perf_event_read_format
    'PERF_FORMAT_TOTAL_TIME_ENABLED' => 1 << 0,
    'PERF_FORMAT_TOTAL_TIME_RUNNING' => 1 << 1,
    'PERF_FORMAT_ID'                 => 1 << 2,
    'PERF_FORMAT_GROUP'              => 1 << 3,
    'PERF_FORMAT_LOST'               => 1 << 4,
    'PERF_FORMAT_MAX'                => 1 << 5,    # non-ABI

    # enum: perf_event_ioc_flags
    'PERF_IOC_FLAG_GROUP' => 1 << 0,

    # enum: perf_record_ksymbol_type
    'PERF_RECORD_KSYMBOL_TYPE_UNKNOWN' => 0,
    'PERF_RECORD_KSYMBOL_TYPE_BPF'     => 1,
    'PERF_RECORD_KSYMBOL_TYPE_OOL'     => 2,
    'PERF_RECORD_KSYMBOL_TYPE_MAX'     => 3,       # non-ABI

    # enum: perf_bpf_event_type
    'PERF_BPF_EVENT_UNKNOWN'     => 0,
    'PERF_BPF_EVENT_PROG_LOAD'   => 1,
    'PERF_BPF_EVENT_PROG_UNLOAD' => 2,
    'PERF_BPF_EVENT_MAX'         => 3,             # non-ABI

    # enum: perf_callchain_context
    'PERF_CONTEXT_HV'           => -32,
    'PERF_CONTEXT_KERNEL'       => -128,
    'PERF_CONTEXT_USER'         => -512,
    'PERF_CONTEXT_GUEST'        => -2048,
    'PERF_CONTEXT_GUEST_KERNEL' => -2176,
    'PERF_CONTEXT_GUEST_USER'   => -2560,
    'PERF_CONTEXT_MAX'          => -4095,

    # define: PERF_PMU_TYPE_SHIFT
    'PERF_PMU_TYPE_SHIFT' => 32,

    # define: PERF_HW_EVENT_MASK
    'PERF_HW_EVENT_MASK' => 0xffffffff,

    # define: PERF_SAMPLE_BRANCH_PLM_ALL
    'PERF_SAMPLE_BRANCH_PLM_ALL' => ( 1 << 0 ) | ( 1 << 1 ) | ( 1 << 2 ),

    # define: PERF_SAMPLE_WEIGHT_TYPE
    'PERF_SAMPLE_WEIGHT_TYPE' => ( 1 << 14 ) | ( 1 << 24 ),

    # define: PERF_MAX_*
    'PERF_MAX_STACK_DEPTH'        => 127,
    'PERF_MAX_CONTEXTS_PER_STACK' => 8,

    # define: PERF_RECORD_MISC_*
    'PERF_RECORD_MISC_CPUMODE_MASK'           => ( 7 << 0 ),
    'PERF_RECORD_MISC_CPUMODE_UNKNOWN'        => ( 0 << 0 ),
    'PERF_RECORD_MISC_KERNEL'                 => ( 1 << 0 ),
    'PERF_RECORD_MISC_USER'                   => ( 2 << 0 ),
    'PERF_RECORD_MISC_HYPERVISOR'             => ( 3 << 0 ),
    'PERF_RECORD_MISC_GUEST_KERNEL'           => ( 4 << 0 ),
    'PERF_RECORD_MISC_GUEST_USER'             => ( 5 << 0 ),
    'PERF_RECORD_MISC_PROC_MAP_PARSE_TIMEOUT' => ( 1 << 12 ),
    'PERF_RECORD_MISC_MMAP_DATA'              => ( 1 << 13 ),
    'PERF_RECORD_MISC_COMM_EXEC'              => ( 1 << 13 ),
    'PERF_RECORD_MISC_FORK_EXEC'              => ( 1 << 13 ),
    'PERF_RECORD_MISC_SWITCH_OUT'             => ( 1 << 13 ),
    'PERF_RECORD_MISC_EXACT_IP'               => ( 1 << 14 ),
    'PERF_RECORD_MISC_SWITCH_OUT_PREEMPT'     => ( 1 << 14 ),
    'PERF_RECORD_MISC_MMAP_BUILD_ID'          => ( 1 << 14 ),
    'PERF_RECORD_MISC_EXT_RESERVED'           => ( 1 << 15 ),

    # define: PERF_AUX_FLAG_*
    'PERF_AUX_FLAG_TRUNCATED' => 0x01,    # record was truncated to fit
    'PERF_AUX_FLAG_OVERWRITE' => 0x02,    # snapshot from overwrite mode
    'PERF_AUX_FLAG_PARTIAL'   => 0x04,    # record contains gaps
    'PERF_AUX_FLAG_COLLISION' => 0x08,    # sample collided with another
    'PERF_AUX_FLAG_PMU_FORMAT_TYPE_MASK' =>
        0xff00,                           # PMU specific trace format type
    'PERF_AUX_FLAG_CORESIGHT_FORMAT_CORESIGHT' =>
        0x0000,                           # Default for backward compatibility
    'PERF_AUX_FLAG_CORESIGHT_FORMAT_RAW' => 0x0100, # Raw format of the source

    # define: PERF_FLAG_*
    'PERF_FLAG_FD_NO_GROUP' => 1 << 0,
    'PERF_FLAG_FD_OUTPUT'   => 1 << 1,
    'PERF_FLAG_PID_CGROUP'  => 1 << 2,    # pid=cgroup id, per-cpu mode only
    'PERF_FLAG_FD_CLOEXEC'  => 1 << 3,    # O_CLOEXEC

    # define: PERF_MEM_OP_*
    'PERF_MEM_OP_NA'     => 0x01,
    'PERF_MEM_OP_LOAD'   => 0x02,
    'PERF_MEM_OP_STORE'  => 0x04,
    'PERF_MEM_OP_PFETCH' => 0x08,
    'PERF_MEM_OP_EXEC'   => 0x10,
    'PERF_MEM_OP_SHIFT'  => 0,

    # define: PERF_MEM_LVL_*
    'PERF_MEM_LVL_NA'       => 0x01,
    'PERF_MEM_LVL_HIT'      => 0x02,
    'PERF_MEM_LVL_MISS'     => 0x04,
    'PERF_MEM_LVL_L1'       => 0x08,
    'PERF_MEM_LVL_LFB'      => 0x10,
    'PERF_MEM_LVL_L2'       => 0x20,
    'PERF_MEM_LVL_L3'       => 0x40,
    'PERF_MEM_LVL_LOC_RAM'  => 0x80,
    'PERF_MEM_LVL_REM_RAM1' => 0x100,
    'PERF_MEM_LVL_REM_RAM2' => 0x200,
    'PERF_MEM_LVL_REM_CCE1' => 0x400,
    'PERF_MEM_LVL_REM_CCE2' => 0x800,
    'PERF_MEM_LVL_IO'       => 0x1000,
    'PERF_MEM_LVL_UNC'      => 0x2000,
    'PERF_MEM_LVL_SHIFT'    => 5,

    # define: PERF_MEM_REMOTE_*
    'PERF_MEM_REMOTE_REMOTE' => 0x01,
    'PERF_MEM_REMOTE_SHIFT'  => 37,

    # define: PERF_MEM_LVLNUM_*
    'PERF_MEM_LVLNUM_L1'        => 0x01,
    'PERF_MEM_LVLNUM_L2'        => 0x02,
    'PERF_MEM_LVLNUM_L3'        => 0x03,
    'PERF_MEM_LVLNUM_L4'        => 0x04,
    'PERF_MEM_LVLNUM_L2_MHB'    => 0x05,
    'PERF_MEM_LVLNUM_MSC'       => 0x06,
    'PERF_MEM_LVLNUM_UNC'       => 0x08,
    'PERF_MEM_LVLNUM_CXL'       => 0x09,
    'PERF_MEM_LVLNUM_IO'        => 0x0a,
    'PERF_MEM_LVLNUM_ANY_CACHE' => 0x0b,
    'PERF_MEM_LVLNUM_LFB'       => 0x0c,
    'PERF_MEM_LVLNUM_RAM'       => 0x0d,
    'PERF_MEM_LVLNUM_PMEM'      => 0x0e,
    'PERF_MEM_LVLNUM_NA'        => 0x0f,
    'PERF_MEM_LVLNUM_SHIFT'     => 33,

    # define: PERF_MEM_SNOOP_*
    'PERF_MEM_SNOOP_NA'    => 0x01,    # not available
    'PERF_MEM_SNOOP_NONE'  => 0x02,    # no snoop
    'PERF_MEM_SNOOP_HIT'   => 0x04,    # snoop hit
    'PERF_MEM_SNOOP_MISS'  => 0x08,    # snoop miss
    'PERF_MEM_SNOOP_HITM'  => 0x10,    # snoop hit modified
    'PERF_MEM_SNOOP_SHIFT' => 19,

    # define: PERF_MEM_SNOOPX_*
    'PERF_MEM_SNOOPX_FWD'   => 0x01,    # forward
    'PERF_MEM_SNOOPX_PEER'  => 0x02,    # xfer from peer
    'PERF_MEM_SNOOPX_SHIFT' => 38,

    # define: PERF_MEM_LOCK_*
    'PERF_MEM_LOCK_NA'     => 0x01,     # not available
    'PERF_MEM_LOCK_LOCKED' => 0x02,     # locked transaction
    'PERF_MEM_LOCK_SHIFT'  => 24,

    # define: PERF_MEM_TLB_*
    'PERF_MEM_TLB_NA'    => 0x01,       # not available
    'PERF_MEM_TLB_HIT'   => 0x02,       # hit level
    'PERF_MEM_TLB_MISS'  => 0x04,       # miss level
    'PERF_MEM_TLB_L1'    => 0x08,       # L1
    'PERF_MEM_TLB_L2'    => 0x10,       # L2
    'PERF_MEM_TLB_WK'    => 0x20,       # Hardware Walker
    'PERF_MEM_TLB_OS'    => 0x40,       # OS fault handler
    'PERF_MEM_TLB_SHIFT' => 26,

    # define: PERF_MEM_BLK_*
    'PERF_MEM_BLK_NA'    => 0x01,       # not available
    'PERF_MEM_BLK_DATA'  => 0x02,       # data could not be forwarded
    'PERF_MEM_BLK_ADDR'  => 0x04,       # address conflict
    'PERF_MEM_BLK_SHIFT' => 40,

    # define: PERF_MEM_HOPS_*
    'PERF_MEM_HOPS_0'     => 0x01,      # remote core, same node
    'PERF_MEM_HOPS_1'     => 0x02,      # remote node, same socket
    'PERF_MEM_HOPS_2'     => 0x03,      # remote socket, same board
    'PERF_MEM_HOPS_3'     => 0x04,      # remote board
                                        # 5-7 available
    'PERF_MEM_HOPS_SHIFT' => 43,

    # define: PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER
    'PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER' => 1 << 0,

    # enum: perf_record_type
    'PERF_RECORD_MMAP'             => 1,
    'PERF_RECORD_LOST'             => 2,
    'PERF_RECORD_COMM'             => 3,
    'PERF_RECORD_EXIT'             => 4,
    'PERF_RECORD_THROTTLE'         => 5,
    'PERF_RECORD_UNTHROTTLE'       => 6,
    'PERF_RECORD_FORK'             => 7,
    'PERF_RECORD_READ'             => 8,
    'PERF_RECORD_SAMPLE'           => 9,
    'PERF_RECORD_MMAP2'            => 10,
    'PERF_RECORD_AUX'              => 11,
    'PERF_RECORD_ITRACE_START'     => 12,
    'PERF_RECORD_LOST_SAMPLES'     => 13,
    'PERF_RECORD_SWITCH'           => 14,
    'PERF_RECORD_SWITCH_CPU_WIDE'  => 15,
    'PERF_RECORD_NAMESPACES'       => 16,
    'PERF_RECORD_KSYMBOL'          => 17,
    'PERF_RECORD_BPF_EVENT'        => 18,
    'PERF_RECORD_CGROUP'           => 19,
    'PERF_RECORD_TEXT_POKE'        => 20,
    'PERF_RECORD_AUX_OUTPUT_HW_ID' => 21,
    'PERF_RECORD_MAX'              => 22,    # non-ABI
);

# Export all constants
our @EXPORT_OK   = keys %constants;
our %EXPORT_TAGS = ( all => \@EXPORT_OK );

# Define constants as subroutines
for my $name (@EXPORT_OK) {
    no strict 'refs';
    *{$name} = sub () { $constants{$name} };
}

1;
