#ifndef _RAID5_LOG_H
#define _RAID5_LOG_H

extern int r5l_init_log(struct r5conf *conf, struct md_rdev *rdev);
extern void r5l_exit_log(struct r5conf *conf);
extern int r5l_write_stripe(struct r5l_log *log, struct stripe_head *head_sh);
extern void r5l_write_stripe_run(struct r5l_log *log);
extern void r5l_flush_stripe_to_raid(struct r5l_log *log);
extern void r5l_stripe_write_finished(struct stripe_head *sh);
extern int r5l_handle_flush_request(struct r5l_log *log, struct bio *bio);
extern void r5l_quiesce(struct r5l_log *log, int state);
extern bool r5l_log_disk_error(struct r5conf *conf);

static inline int log_stripe(struct stripe_head *sh, struct stripe_head_state *s)
{
	struct r5conf *conf = sh->raid_conf;

	if (conf->log)
		return r5l_write_stripe(conf->log, sh);

	return -EAGAIN;
}

static inline void log_stripe_write_finished(struct stripe_head *sh)
{
	struct r5conf *conf = sh->raid_conf;

	if (conf->log)
		r5l_stripe_write_finished(sh);
}

static inline void log_write_stripe_run(struct r5conf *conf)
{
	if (conf->log)
		r5l_write_stripe_run(conf->log);
}

static inline void log_exit(struct r5conf *conf)
{
	if (conf->log)
		r5l_exit_log(conf);
}

static inline int log_init(struct r5conf *conf, struct md_rdev *journal_dev)
{
	if (journal_dev)
		return r5l_init_log(conf, journal_dev);

	return 0;
}

#endif
