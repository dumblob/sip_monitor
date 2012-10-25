/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include "args.h"
#include "monitor.h"

#define MALLOC_EXIT do { fputs("malloc failed!\n"); exit EXIT_FAILURE; } while (0)

#endif
