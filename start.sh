#!/bin/sh

erl $@ -boot start_sasl -pa deps/*/ebin ebin
