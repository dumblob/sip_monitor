/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include "args.h"
#include "monitor.h"
#include "list.h"

int main(int argc, char *argv[])
{
  args_s args;

  /* initialize args and fill with values according to given arguments */
  handle_args(argc, argv, &args);

  /* start monitoring the given interface using libpcap */
  //FIXME retval nejaka specialni a podle ni vypisovat chyby?
  int ret = start_sip_monitoring(&args);

  if (args->f != NULL) list_dispose(args->f);
  if (args->t != NULL) list_dispose(args->t);

  return ret;
}
