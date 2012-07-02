#ifndef COMPAT_H
#define COMPAT_H

enum perf_event_sample_format_compat {
        PERF_SAMPLE_BRANCH_STACK                = 1U << 11,
};

enum perf_branch_sample_type_compat {
	PERF_SAMPLE_BRANCH_USER         = 1U << 0, /* user branches */
	PERF_SAMPLE_BRANCH_KERNEL       = 1U << 1, /* kernel branches */
	PERF_SAMPLE_BRANCH_HV           = 1U << 2, /* hypervisor branches */

	PERF_SAMPLE_BRANCH_ANY          = 1U << 3, /* any branch types */
	PERF_SAMPLE_BRANCH_ANY_CALL     = 1U << 4, /* any call branch */
	PERF_SAMPLE_BRANCH_ANY_RETURN   = 1U << 5, /* any return branch */
	PERF_SAMPLE_BRANCH_IND_CALL     = 1U << 6, /* indirect calls */

	PERF_SAMPLE_BRANCH_MAX          = 1U << 7, /* non-ABI */
};

#define PERF_SAMPLE_BRANCH_PLM_ALL \
	(PERF_SAMPLE_BRANCH_USER|\
	 PERF_SAMPLE_BRANCH_KERNEL|\
	 PERF_SAMPLE_BRANCH_HV)

enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_8 = 8,
};

enum {
	HW_BREAKPOINT_EMPTY     = 0,
	HW_BREAKPOINT_R         = 1,
	HW_BREAKPOINT_W         = 2,
	HW_BREAKPOINT_RW        = HW_BREAKPOINT_R | HW_BREAKPOINT_W,
	HW_BREAKPOINT_X         = 4,
	HW_BREAKPOINT_INVALID   = HW_BREAKPOINT_RW | HW_BREAKPOINT_X,
};

#endif /* COMPAT_H */
