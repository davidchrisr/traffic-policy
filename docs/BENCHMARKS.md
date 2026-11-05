# DNS throughput

Traffic Policy handled **over 5,000 successful DNS queries per second during a
60-second burst on a two-vCPU gateway**, with traffic capture and history
collection enabled.

## Short-burst results

| Metric                                       | Normal-load sanity check | Overload burst |
| -------------------------------------------- | -----------------------: | -------------: |
| Offered queries/s                            |                    4,000 |          8,000 |
| Duration                                     |               20 seconds |     60 seconds |
| Offered queries                              |                   80,000 |        480,000 |
| Successful replies                           |                   80,000 |        346,616 |
| Successful replies/s                         |                    3,995 |          5,757 |
| Median latency                               |                    14 ms |         683 ms |
| p95 latency                                  |                   330 ms |         941 ms |
| SERVFAIL replies                             |                        0 |        133,384 |
| Rejected resolver history observations       |                        0 |         55,045 |
| Lost durable batches at the end of the burst |                        0 |             26 |

All 80,000 resolver history records from the normal-load check reached the
controller. In the overload test, every upstream-forwarded query succeeded;
SERVFAIL replies came from query admission reaching capacity. The client had no
send errors or timeouts. Collector delivery and persistence errors remained
null. Overload history rejections and batch evictions are separate from DNS
reply success; the throughput headline describes successful DNS replies.

## Environment and method

The tests ran on 18 October 2026 with the following fixed Incus allocations:

- Gateway: two vCPUs and 3 GiB RAM.
- Controller: two vCPUs and 2 GiB RAM.
- Client and local DNS upstream: one vCPU and 1 GiB RAM each.

The upstream was entirely local and returned a 60-second TTL. The driver used
UDP A queries across 64 rotating names per run, distinct query IDs and a
10-second client deadline. It offered traffic at a fixed rate rather than
waiting for one reply before sending the next query. The controller started with
a populated database and a 512 MiB history allocation. These are single trials
on a shared host, not measurements of Internet DNS latency or a long-running
steady-state ceiling.

The measured gateway artifact has SHA-256
`4f3ad63f08d5206b694e4baca06460b4ae81dffc90e48187f28e7bee025b4a80`. The
controller runtime has SHA-256
`07b8cc7e59dcf843eb65e8cf605a1f6a09df0cc698a114a072ea308676173e43`.

## Engineering work

The implementation reuses enforcement connections and upstream DNS sockets,
indexes rule candidates, updates learned permissions incrementally, batches
firewall updates and collector writes, and moves collector persistence to a
worker. It avoids kernel readback and redundant history scans. Bounded admission
and backpressure keep overload visible.
