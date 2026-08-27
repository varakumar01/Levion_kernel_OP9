// SPDX-License-Identifier: GPL-2.0-only
#include "stealth_net.h"

static DECLARE_KFIFO(events_fifo, struct stealth_event, EVENT_FIFO_SIZE);
static DEFINE_SPINLOCK(fifo_lock);

void events_fifo_init(void)
{
	INIT_KFIFO(events_fifo);
}

void events_fifo_flush(void)
{
	spin_lock_bh(&fifo_lock);
	kfifo_reset(&events_fifo);
	spin_unlock_bh(&fifo_lock);
}

bool events_fifo_has_data(void)
{
	bool has_data;

	spin_lock_bh(&fifo_lock);
	has_data = !kfifo_is_empty(&events_fifo);
	spin_unlock_bh(&fifo_lock);

	return has_data;
}

void push_event(uid_t uid, u8 action, u8 ip_ver, const char *domain)
{
	struct stealth_event ev;
	struct stealth_event dropped;
	int ev_len = sizeof(ev);
	int dom_len = sizeof(ev.domain);
	bool pushed;

	memset(&ev, 0, ev_len);
	ev.uid = uid;
	ev.action = action;
	ev.ip_ver = ip_ver;

	strscpy(ev.domain, domain ? domain : "-", dom_len);

	spin_lock_bh(&fifo_lock);
	pushed = kfifo_put(&events_fifo, ev);
	if (unlikely(!pushed)) {
		kfifo_get(&events_fifo, &dropped);
		pushed = kfifo_put(&events_fifo, ev);
	}
	spin_unlock_bh(&fifo_lock);

	if (likely(pushed))
		stealth_notify_event();
}

bool pop_event(struct stealth_event *ev)
{
	bool ret;

	if (unlikely(!ev))
		return false;

	spin_lock_bh(&fifo_lock);
	ret = kfifo_get(&events_fifo, ev);
	spin_unlock_bh(&fifo_lock);

	return ret;
}
