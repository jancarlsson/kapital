CXX = g++
CXXFLAGS = -O2 -g3 -std=c++11 -I.

RM = rm
LN = ln
AR = ar
RANLIB = ranlib

LIBRARY_HPP = \
	AddressKey.hpp \
	Coin.hpp \
	EncryptedCoin.hpp \
	HashFunctions.hpp \
	PourBody.hpp \
	PourInput.hpp \
	PourTX.hpp \
	PourZKP.hpp \
	ProvePour.hpp \
	SignatureKey.hpp \
	Variable.hpp \
	VerifyPour.hpp

CLEAN_FILES = \
	README.html \
	smoketest

default :
	@echo Build options:
	@echo make smoketest PREFIX=\<path\>
	@echo make install PREFIX=\<path\>
	@echo make doc
	@echo make clean

README.html : README.md
	markdown_py -f README.html README.md -x toc -x extra --noisy

doc : README.html

clean :
	rm -f *.o $(CLEAN_FILES) kapital

ifeq ($(PREFIX),)
smoketest :
	$(error Please provide PREFIX, e.g. make smoketest PREFIX=/usr/local)

install :
	$(error Please provide PREFIX, e.g. make install PREFIX=/usr/local)
else
CXXFLAGS_PREFIX = \
	-I$(PREFIX)/include \
	-I$(PREFIX)/include/cryptopp \
	-DUSE_ASM -DUSE_ADD_SPECIAL -DUSE_ASSERT

LDFLAGS_PREFIX = \
	-L$(PREFIX)/lib \
	-lsnarkfront -lgmpxx -lgmp -lcryptopp

AR_FLAGS = $(CXXFLAGS) $(CXXFLAGS_PREFIX)

kapital :
	$(RM) -f kapital
	$(LN) -s . kapital

smoketest : smoketest.cpp kapital
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_PREFIX) $< -o smoketest.o
	$(CXX) -o $@ smoketest.o $(LDFLAGS_PREFIX)

install :
	mkdir -p $(PREFIX)/include/kapital
	cp $(LIBRARY_HPP) $(PREFIX)/include/kapital
endif
