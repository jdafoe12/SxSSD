#ifndef FEMU_POLICY_QTAILQ_H
#define FEMU_POLICY_QTAILQ_H

#if defined(__has_include)
#if __has_include(<sys/queue.h>)
#include <sys/queue.h>
#define FEMU_POLICY_HAVE_SYS_QUEUE 1
#endif
#endif

#ifndef FEMU_POLICY_HAVE_SYS_QUEUE
#define TAILQ_HEAD(name, type)                                                \
struct name {                                                                 \
    struct type *tqh_first;                                                    \
    struct type **tqh_last;                                                    \
}

#define TAILQ_ENTRY(type)                                                      \
struct {                                                                       \
    struct type *tqe_next;                                                     \
    struct type **tqe_prev;                                                    \
}

#define TAILQ_INIT(head) do {                                                  \
    (head)->tqh_first = (void *)0;                                             \
    (head)->tqh_last = &(head)->tqh_first;                                     \
} while (0)

#define TAILQ_FIRST(head) ((head)->tqh_first)

#define TAILQ_INSERT_TAIL(head, elm, field) do {                               \
    (elm)->field.tqe_next = (void *)0;                                         \
    (elm)->field.tqe_prev = (head)->tqh_last;                                  \
    *(head)->tqh_last = (elm);                                                 \
    (head)->tqh_last = &(elm)->field.tqe_next;                                 \
} while (0)

#define TAILQ_REMOVE(head, elm, field) do {                                    \
    if ((elm)->field.tqe_next != (void *)0) {                                  \
        (elm)->field.tqe_next->field.tqe_prev = (elm)->field.tqe_prev;         \
    } else {                                                                   \
        (head)->tqh_last = (elm)->field.tqe_prev;                              \
    }                                                                          \
    *(elm)->field.tqe_prev = (elm)->field.tqe_next;                            \
} while (0)
#endif

#define QTAILQ_HEAD(name, type) TAILQ_HEAD(name, type)
#define QTAILQ_ENTRY(type) TAILQ_ENTRY(type)
#define QTAILQ_INIT(head) TAILQ_INIT(head)
#define QTAILQ_FIRST(head) TAILQ_FIRST(head)
#define QTAILQ_INSERT_TAIL(head, elm, field) TAILQ_INSERT_TAIL(head, elm, field)
#define QTAILQ_REMOVE(head, elm, field) TAILQ_REMOVE(head, elm, field)

#endif /* FEMU_POLICY_QTAILQ_H */
