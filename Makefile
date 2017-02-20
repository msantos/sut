.PHONY: all compile clean examples eg

REBAR ?= rebar3

all: clean compile

compile:
	@$(REBAR) compile

clean:
	@$(REBAR) clean

examples: eg
eg:
	@erlc -I deps -o ebin examples/*.erl
