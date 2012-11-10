/*
 * Jan Pacner xpacne00@stud.fit.vutbr.cz
 * 2012-10-15 10:28:53 CEST
 */

#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>  /* exit */
#include <unistd.h>  /* getopt */
#include "list_str.h"
#include "args.h"

//FIXME testovat uplne libovolne poradi argumentu

/*
 * promiskuitni mod -> vyfiltruje pouze SIP zpravy
 * spusteni bez parametru vypise napovedu + muj login + exit(0)
 * defaultne vypisuje info o
 *   navazanych/accepted hovorech (tzn. prijatych druhou stranou)
 *   zahajeni hovoru (vypsat casove razitko + kdo komu vola)
 *   ukonceni hovoru (- || -                               + delka hovoru)
 * argumenty
 *   -i <ethernet_interface>
 *     POZOR je povinny
 *           muze byt zadan pouze 1x
 *   -a
 *     vypise info i o neprijatych hovorech (prozvoneni, odmitnuti) +
 *     duvod neprijeti
 *     POZOR nesmi byt spolu s -c
 *           muze byt zadan pouze 1x
 *   -c
 *     pouze info o dokoncenych hovorech (tzn. chybi info o zahajeni)
 *     POZOR nesmi byt spolu s -a
 *           muze byt zadan pouze 1x
 *   -f <id>
 *     vypise pouze hovory iniciovane od <id>
 *     POZOR muze byt zadano i vicekrat (i to same vicekrat)
 *           lze kombinovat s cimkoliv (i -t, i -u)
 *   -t <id>
 *     vypise pouze hovory iniciovane pro <id>
 *     POZOR muze byt zadano i vicekrat (i to same vicekrat)
 *           lze kombinovat s cimkoliv (i -f, i -u)
 *   -u <id>
 *     vypise pouze hovory iniciovane od <id> nebo pro <id>
 *     POZOR muze byt zadano i vicekrat (i to same vicekrat)
 *           lze kombinovat s cimkoliv (i -t, i -f)
 */

void handle_args(int argc, char *argv[], args_s *args)
{
  args->implicit = true;
  args->i        = NULL;
  args->a        = false;
  args->c        = false;
  args->f        = NULL;
  args->t        = NULL;

  /* help */
  if (argc == 1)
  {
    printf(
        "SYNOPSIS\n"
        "  %s -i <eth_int> [-a|-c] [-f <id>] [-t <id>] [-u <id>]\n"
        "OPTIONS\n"
        "  -i <eth_int>\n"
        "     ethernet interface to operate on\n"
        "     mandatory, allowed only once\n"
        "  -a\n"
        "     put info about declined calls too\n"
        "     optional, allowed only once\n"
        "     conflicts with: -c\n"
        "  -c\n"
        "     put info only about finished calls\n"
        "     optional, allowed only once\n"
        "     conflicts with: -a\n"
        "  -f <id>\n"
        "     put only calls from the given call ID\n"
        "     optional, allowed more than once\n"
        "  -t <id>\n"
        "     put only calls to the given call ID\n"
        "     optional, allowed more than once\n"
        "  -u <id>\n"
        "     put only calls from or to the given call ID\n"
        "     optional, allowed more than once\n"
        "AUTHOR\n"
        "  Jan Pacner xpacne00@stud.fit.vutbr.cz\n", argv[0]);

    exit(EXIT_SUCCESS);
  }

  int opt;
  opterr = 0;  // disable getopt() writing to stderr

  while ((opt = getopt(argc, argv, "+i:acf:t:u:")) != -1)
  {
    switch (opt)
    {
      case 'i':
        if (args->i == NULL)
        {
          args->i = argv[optind -1];
          break;
        }
        else
        {
          fputs("Argument -i can be given only once!\n", stderr);
          exit(EXIT_FAILURE);
        }

      case 'a':
        if (args->a == false)
        {
          if (args->c)
          {
            fputs("Argument -a conflicts with -c!\n", stderr);
            exit(EXIT_FAILURE);
          }

          args->a = true;
          break;
        }
        else
        {
          fputs("Argument -a can be given only once!\n", stderr);
          exit(EXIT_FAILURE);
        }

      case 'c':
        if (args->c == false)
        {
          if (args->a)
          {
            fputs("Argument -c conflicts with -a!\n", stderr);
            exit(EXIT_FAILURE);
          }

          args->c = true;
          break;
        }
        else
        {
          fputs("Argument -c can be given only once!\n", stderr);
          exit(EXIT_FAILURE);
        }

      case 'f':
        if (args->f == NULL) args->f = list_str_init();

        if (! list_str_item_present(args->f, optarg))
          list_str_add(args->f, optarg);

        break;

      case 't':
        if (args->t == NULL) args->t = list_str_init();

        if (! list_str_item_present(args->t, optarg))
          list_str_add(args->t, optarg);

        break;

      case 'u':
        if (args->f == NULL) args->f = list_str_init();

        if (args->t == NULL) args->t = list_str_init();

        if (! list_str_item_present(args->f, optarg))
          list_str_add(args->f, optarg);

        if (! list_str_item_present(args->t, optarg))
          list_str_add(args->t, optarg);

        break;

      /* '?' */
      default:
        fprintf(stderr, "Unknown argument \"%s\" given.\n", argv[optind -1]);
        exit(EXIT_FAILURE);
    }
  }

  /* optind points to next argument (after the current one) in argv */
  if (optind != argc)
  {
    assert(optind < argc);
    fprintf(stderr, "Unknown argument \"%s\" given!\n", argv[optind]);
    exit(EXIT_FAILURE);
  }

  if (args->i == NULL)
  {
    fputs("The argument -i is mandatory!\n", stderr);
    exit(EXIT_FAILURE);
  }

  if (args->a || args->c) args->implicit = false;
}
