srcdir = .


doofus:
	@echo ""
	@echo "Let's try this from the right directory..."
	@echo ""
	@cd ../../../ && make

static: ../last.o

modules: ../../../last.$(MOD_EXT)

../last.o:
	echo $(CC) $(CFLAGS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -DMAKING_MODS -c $(srcdir)/last.c
	@rm -f ../last.o
	mv last.o ../

../../../last.$(MOD_EXT): ../last.o
	$(LD) -lutil  -o ../../../last.$(MOD_EXT) ../last.o $(XLIBS) $(MODULE_XLIBS)
	$(STRIP) ../../../last.$(MOD_EXT)

depend:
	$(CC) $(CFLAGS) -MM $(srcdir)/last.c -MT ../last.o > .depend

clean:
	@rm -f .depend *.o *.$(MOD_EXT) *~

distclean: clean


