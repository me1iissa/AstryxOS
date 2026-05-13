# libfontconfig-interposer — defensive FcPatternGetString wrapper for
# firefox-test.  Loaded via LD_PRELOAD before real libfontconfig.so.1.
#
# Build host: linux/x86_64.  Outputs a position-independent shared
# object that depends only on libdl (for dlsym).
#
# Used by scripts/create-data-disk.sh to stage the .so into
# build/disk/lib64/.  The build is idempotent and respects $(SONAME) /
# $(OUTDIR) overrides from the caller script.

SONAME ?= libfontconfig-interposer.so
OUTDIR ?= .
SRC    := interposer.c
OUT    := $(OUTDIR)/$(SONAME)

CC      ?= gcc
CFLAGS  ?= -O2 -fPIC -Wall -Wextra
LDFLAGS ?= -shared -Wl,-soname,$(SONAME) -ldl

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRC)
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(OUT)
