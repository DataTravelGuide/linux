#ifndef __IPC_NAMESPACE_H__
#define __IPC_NAMESPACE_H__

#include <linux/err.h>
#include <linux/idr.h>
#include <linux/rwsem.h>
#include <linux/notifier.h>

/*
 * ipc namespace events
 */
#define IPCNS_MEMCHANGED   0x00000001   /* Notify lowmem size changed */
#define IPCNS_CREATED  0x00000002   /* Notify new ipc namespace created */
#define IPCNS_REMOVED  0x00000003   /* Notify ipc namespace removed */

#define IPCNS_CALLBACK_PRI 0


struct ipc_ids {
	int in_use;
	unsigned short seq;
	unsigned short seq_max;
	struct rw_semaphore rw_mutex;
	struct idr ipcs_idr;
};

struct ipc_namespace {
	atomic_t	count;
	struct ipc_ids	ids[3];

	int		sem_ctls[4];
	int		used_sems;

	int		msg_ctlmax;
	int		msg_ctlmnb;
	int		msg_ctlmni;
	atomic_t	msg_bytes;
	atomic_t	msg_hdrs;
	int		auto_msgmni;

	size_t		shm_ctlmax;
	size_t		shm_ctlall;
	int		shm_ctlmni;
	int		shm_tot;

	struct notifier_block ipcns_nb;

	/* The kern_mount of the mqueuefs sb.  We take a ref on it */
	struct vfsmount	*mq_mnt;

	/* # queues in this ns, protected by mq_lock */
	unsigned int    mq_queues_count;

	/* next fields are set through sysctl */
	unsigned int    mq_queues_max;   /* initialized to DFLT_QUEUESMAX */
	unsigned int    mq_msg_max;      /* initialized to DFLT_MSGMAX */
	unsigned int    mq_msgsize_max;  /* initialized to DFLT_MSGSIZEMAX */

};

extern struct ipc_namespace init_ipc_ns;
extern atomic_t nr_ipc_ns;

extern spinlock_t mq_lock;
#if defined(CONFIG_POSIX_MQUEUE) || defined(CONFIG_SYSVIPC)
#define INIT_IPC_NS(ns)		.ns		= &init_ipc_ns,
#else
#define INIT_IPC_NS(ns)
#endif

#ifdef CONFIG_SYSVIPC
extern int register_ipcns_notifier(struct ipc_namespace *);
extern int cond_register_ipcns_notifier(struct ipc_namespace *);
extern void unregister_ipcns_notifier(struct ipc_namespace *);
extern int ipcns_notify(unsigned long);
#else /* CONFIG_SYSVIPC */
static inline int register_ipcns_notifier(struct ipc_namespace *ns)
{ return 0; }
static inline int cond_register_ipcns_notifier(struct ipc_namespace *ns)
{ return 0; }
static inline void unregister_ipcns_notifier(struct ipc_namespace *ns) { }
static inline int ipcns_notify(unsigned long l) { return 0; }
#endif /* CONFIG_SYSVIPC */

#ifdef CONFIG_POSIX_MQUEUE
extern int mq_init_ns(struct ipc_namespace *ns);
/* 
 * Default values:
 * MIN_*: Used as the lowest allowed user selectable value if attributes are
 *   passed in to the create call for message queues
 * DFLT_*: Used as the system wide default maximum values applied to normal,
 *   unprivileged programs.  These are what is used to initially set the values
 *   for the namespace in mq_init_ns().  The maximum values for unprivileged
 *   applications can be raised by setting the respective items in
 *   /proc/sys/fs/mqueue/
 * HARD_*: These are the system wide hard maximums applied to privileged
 *   applications.  The system admin can increase the unprivileged maximums
 *   only up to these hard limits, and privileged applications can only create
 *   queues up to these hard limits.  They are inviolate.
 * NOTE: While it is possible to raise both MSGMAX and MSGSIZEMAX to their
 *   maximum hard limits, it is not possible to create a queue with
 *   those values set to their hard limits.  This is due to the fact that
 *   msgmax * msgsizemax must not wrap a 32bit counter, and with both
 *   items set to thier maximum, it will.  In that case, the queue will
 *   be rejected at creation time.  Further, the sum of msgmax * msgsizemax
 *   for all queues attached to a single process can not wrap that same
 *   32bit counter, so even a perfectly valid size of queue can be
 *   rejected if the application already has too many other queues open
 *   and the size of this queue in addition to its other queues would
 *   exceed the size of that 32bit counter.
 *
 * *_QUEUESMAX: Maximum number of message queues per message queue namespace.
 *   We account message queues on a per namespace basis, however POSIX
 *   mandates that we allow a minimum maximum of 8 message queues to be
 *   opened per process.  There is no direct mapping of how we account
 *   message queue counts onto this POSIX mandate, so we set the default
 *   minimum such that it's unlikely any application will have a problem
 *   opening 8 queues if they so desire.
 * *_MSGMAX: Maximum of number of messages in a queue.  POSIX mandates that
 *   we support a minimum hard maximum of at least 32767.
 * *_MSGSIZEMAX: Maximum size of a message in a queue.  POSIX is silent on
 *   this option.  However, we know that there are existing users of Linux
 *   that rely upon MSGSIZEMAX being at least 5MBytes, with a preference
 *   for 10MBytes (discovered after the last change when MSGSIZEMAX was
 *   reduced from INT_MAX to 8192*128, breaking these current user's
 *   running configurations).
 */
#define MIN_QUEUESMAX 		    1
#define DFLT_QUEUESMAX		   32
#define HARD_QUEUESMAX		 1024
#define MIN_MSGMAX		    1
#define DFLT_MSGMAX		   16
#define HARD_MSGMAX		65536
#define MIN_MSGSIZEMAX		  128
#define DFLT_MSGSIZEMAX	     256*1024
#define HARD_MSGSIZEMAX	 16*1024*1024
#else
static inline int mq_init_ns(struct ipc_namespace *ns) { return 0; }
#endif

#if defined(CONFIG_IPC_NS)
extern struct ipc_namespace *copy_ipcs(unsigned long flags,
				       struct ipc_namespace *ns);
static inline struct ipc_namespace *get_ipc_ns(struct ipc_namespace *ns)
{
	if (ns)
		atomic_inc(&ns->count);
	return ns;
}

extern void put_ipc_ns(struct ipc_namespace *ns);
#else
static inline struct ipc_namespace *copy_ipcs(unsigned long flags,
		struct ipc_namespace *ns)
{
	if (flags & CLONE_NEWIPC)
		return ERR_PTR(-EINVAL);

	return ns;
}

static inline struct ipc_namespace *get_ipc_ns(struct ipc_namespace *ns)
{
	return ns;
}

static inline void put_ipc_ns(struct ipc_namespace *ns)
{
}
#endif

#ifdef CONFIG_POSIX_MQUEUE_SYSCTL

struct ctl_table_header;
extern struct ctl_table_header *mq_register_sysctl_table(void);

#else /* CONFIG_POSIX_MQUEUE_SYSCTL */

static inline struct ctl_table_header *mq_register_sysctl_table(void)
{
	return NULL;
}

#endif /* CONFIG_POSIX_MQUEUE_SYSCTL */
#endif
