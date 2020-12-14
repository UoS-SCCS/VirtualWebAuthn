# =============================================================================
#  Makefile for test_wa_tpm_2
# =============================================================================

# Set paths and flags for TPM_experiments
include ../../makefile-ibm

# Set executable names
LD=g++
RM=rm -rf

# build flags
CXXFLAGS=$(COMMON_CPPFLAGS) $(CXXFLAGS_COMMON) -pg -O2
LDFLAGS= -pg $(LDFLAGS_COMMON) 

# libraries
LDLIBS=$(LDLIBS_COMMON) -lssl -lcrypto  -L$(LIB_DIR) -lwatpm

TARGET=$(PREFIX)test_wa_tpm_2
SRCS=Test_wa_tpm_2.cpp

$(TARGET): $(SRCS:.cpp=.o)
	$(LD) $(TARGET_ARCH) $(LDFLAGS) $(SRCS:.cpp=.o) $(LDLIBS) -o $@

clean:
	$(RM) *.o .d gmon.out *.bin $(TARGET) *~ 

#------------------------------------------------------------------------------
# Makefile method from:
#     http://make.mad-scientist.net/papers/advanced-auto-dependency-generation/
# This implementation places dependency files into a subdirectory named .d.
DEPDIR := .d

# Unfortunately GCC will not create subdirectories, so this line ensures that
# the DEPDIR directory always exists.
$(shell mkdir -p $(DEPDIR) >/dev/null)

# These are the special GCC-specific flags which convince the compiler to
# generate the dependency file. Full descriptions can be found in the GCC
# manual section Options Controlling the Preprocessor
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td

COMPILE.c = $(CC) $(DEPFLAGS) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
COMPILE.cc = $(CXX) $(DEPFLAGS) $(CXXFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

# First rename the generated temporary dependency file to the real dependency
# file. We do this in a separate step so that failures during the compilation
# won�t leave a corrupted dependency file. Second touch the object file; it�s
# been reported that some versions of GCC may leave the object file older than
#the dependency file, which causes unnecessary rebuilds.
POSTCOMPILE = @mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d && touch $@

# Delete the built-in rules for building object files from .c files, so that our
# rule is used instead. Do the same for the other built-in rules.
%.o : %.c

# Declare the generated dependency file as a prerequisite of the TARGET, so that
# if it�s missing the TARGET will be rebuilt.
%.o : %.c $(DEPDIR)/%.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o : %.cc
%.o : %.cc $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

%.o : %.cpp
%.o : %.cpp $(DEPDIR)/%.d
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
	$(POSTCOMPILE)

# Create a pattern rule with an empty recipe, so that make won't fail if the
# dependency file doesn�t exist.
$(DEPDIR)/%.d: ;

# Mark the dependency files precious to make, so they won't be automatically
# deleted as intermediate files.
.PRECIOUS: $(DEPDIR)/%.d

# include the dependency files that exist: translate each file listed in SRCS
# into its dependency file. Use wildcard to avoid failing on non-existent files.
include $(wildcard $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS))))

#------------------------------------------------------------------------------
