/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <signal.h>
#include "args.h"
#include "monitor.h"
#include "list.h"
#include "common.h"

void sa_handler(int x)
{
  pcap_breakloop(global_vars.handle);
}

int main(int argc, char *argv[])
{
  /* init global structure */
  global_vars.handle = NULL;

  /* http://www.kiv.zcu.cz/~luki/vyuka/stare-materialy/os/oslinux/2.0.31/hajic/sluzby.htm#sigaction */
  sigseg_t sigblock;
  sigfillset(&sigblock);
  struct sigaction signew = {
    .sa_handler = sa_handler,
    .sa_mask    = sigblock,
    .sa_flags   = 0,
    .sigaction  = NULL,
  };

  sigaction(SIGTERM, &signew, NULL);  /* termination */
  sigaction(SIGHUP,  &signew, NULL);  /* hangup */
  sigaction(SIGINT,  &signew, NULL);  /* interrupt */

  args_s args;
  /* initialize args and fill with values according to given arguments */
  handle_args(argc, argv, &args);

  /* start monitoring on the given interface using libpcap */
  int ret = start_sip_monitoring(&args);

  if (args->f != NULL) list_dispose(args->f);
  if (args->t != NULL) list_dispose(args->t);

  return ret;
}
