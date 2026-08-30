/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2024 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#ifndef _FIE_H_
#define _FIE_H_

#include <linux/cpumask.h>
#include <linux/jump_label.h>
#include <linux/types.h>

struct rq;

struct fie_rate_info {
	u64 set_time;
	unsigned int freq;
};

/*
 * Exported so qcom-cpufreq-hw.c can skip its own arch_set_freq_scale() call
 * once FIE is measuring frequency itself -- this tree bypasses the
 * scale_freq_data source-arbitration mechanism FIE's source tree uses for
 * this same purpose (see kernel/sched/fie.c's fie_init() comment).
 */
DECLARE_STATIC_KEY_FALSE(fie_ready);

void fie_update_rq_clock(struct rq *rq);
void fie_init_cpu_domain(const struct cpumask *cpus, unsigned int max_freq);
void fie_cpufreq_pressure(int cpu, unsigned int capped_freq);
void fie_rate_set(int cpu, unsigned int freq);

/* Called directly from scheduler_tick() and cpuidle_enter_state() */
void update_cpu_hw_throttle(void);
void fie_cpu_idle(int cpu, bool idle);

#endif /* _FIE_H_ */
