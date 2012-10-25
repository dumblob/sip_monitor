# make [ | all | debug | doc | submit | clean ]

HDR = main.h args.h list.h monitor.h
SRC = main.c args.c list.c monitor.c
EXE ?= sip_monitor
SUB ?= xpacne00
DOCNAME = manual
CC ?= gcc
CFLAGS ?= -std=c99 -W -Wall -Wextra -Werror -pedantic #-lm

OBJ = $(SRC:.c=.o)

all: $(EXE)

debug: CFLAGS += -DDEBUG -g -ggdb3
debug: CC += -DDEBUG -g
debug: all

$(EXE): $(OBJ)
	$(CC) $(CFLAGS) -O2 -o $@ $(OBJ)

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
	$(CC) $(CFLAGS) -c $<
