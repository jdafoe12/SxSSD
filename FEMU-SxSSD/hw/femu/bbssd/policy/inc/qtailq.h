/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef FEMU_POLICY_QTAILQ_H
#define FEMU_POLICY_QTAILQ_H

#include <sys/queue.h>

#define QTAILQ_HEAD(name, type) TAILQ_HEAD(name, type)
#define QTAILQ_ENTRY(type) TAILQ_ENTRY(type)
#define QTAILQ_INIT(head) TAILQ_INIT(head)
#define QTAILQ_FIRST(head) TAILQ_FIRST(head)
#define QTAILQ_INSERT_TAIL(head, elm, field) TAILQ_INSERT_TAIL(head, elm, field)
#define QTAILQ_REMOVE(head, elm, field) TAILQ_REMOVE(head, elm, field)

#endif /* FEMU_POLICY_QTAILQ_H */
