# SPDX-License-Identifier: GPL-2.0

TEST_INCLUDES := $(wildcard lib/py/*.py)

TEST_PROGS := \
	ping.py \
	psp.py \
	stats.py \
# end of TEST_PROGS

# YNL files
YNL_GEN_FILES := psp_responder
TEST_GEN_FILES += $(YNL_GEN_FILES)

include ../../lib.mk

# YNL build
YNL_GENS := psp

include ../../net/ynl.mk
