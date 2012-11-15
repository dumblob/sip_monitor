# make [ | all | debug | doc | submit | clean ]

HDR = common.h args.h list_str.h list_sip.h monitor.h
SRC = args.c list_str.c list_sip.c monitor.c main.c
EXE ?= sip_monitor
SUB ?= xpacne00
DOCNAME = manual
CC ?= gcc
CFLAGS ?= -std=c99 -W -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200112L -lpcap -lrt -lm

OBJ = $(SRC:.c=.o)

all: $(EXE)

debug: CFLAGS += -DDEBUGG -g3
debug: all

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

# article | report | book | memoir | letter | slides (transparent folie)
doc:
	pandoc -S -s --toc -N --section-divs --no-tex-ligatures \
		--variable lang=czech \
		--variable date="$(shell date "+%d. %m. %Y")" \
		--variable geometry=margin=2.5cm \
		--variable geometry=a4paper \
		--variable fontsize=11pt \
		--variable documentclass=report \
		--include-in-header=header.include \
		-o $(DOCNAME).pdf $(DOCNAME).markdown
#report article
#		--template=template.latex

submit: $(doc)
	cd ../ && tar cvf $(SUB).tar \
		$(SUB)/$(SRC) \
		$(SUB)/$(HDR) \
		$(SUB)/Makefile \
		$(SUB)/Readme \
		$(SUB)/$(DOCNAME).pdf

clean:
	rm -f $(OBJ) $(EXE) $(SUB).tar *~

.c.o:
	$(CC) $(CFLAGS) -O2 -c $<
