/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef MONITOR_H
#define MONITOR_H

#define RING_BUF_SIZE 8192  /* for 1 packet */
#define READ_TIMEOUT 300  /* ms */

#include <pcap/pcap.h>
#include "main.h"

int start_sip_monitoring(args_s *);

#endif
