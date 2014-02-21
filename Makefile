XBUILD=xbuild
XBUILD_ARGS=/verbosity:quiet /nologo /p:DefineConstants="MONO DEBUG" /p:Configuration=Debug
MAIN_SLN=simpletorrent.sln

all:
	@echo Building $(MAIN_SLN)
	@$(XBUILD) $(XBUILD_ARGS) $(MAIN_SLN)
	@cp -R simpletorrent/WebApplication build/web

clean:
	@echo Cleaning $(MAIN_SLN)
	@$(XBUILD) $(XBUILD_ARGS) $(MAIN_SLN) /t:Clean

.PHONY: all clean
