# File Encryptor Makefile for Windows with GCC

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic
INCLUDES = -I./include -I./src

# Aggressive compilation flags
AGGRESSIVE_FLAGS = -O3 -march=native -flto -ffast-math -funroll-loops -fomit-frame-pointer

# Output executable name
TARGET = file_encryptor.exe

# Source files - explicitly list to ensure constants.cpp is included
SRCS = $(wildcard src/*.cpp) $(wildcard src/*/*.cpp)
OBJS = $(SRCS:.cpp=.o)

# Main target
all: $(TARGET)

# Link rule
$(TARGET): $(OBJS)
	@echo Linking $(TARGET)...
	$(CXX) -o $@ $^ $(CXXFLAGS)
	@echo Build complete!

# Compile rule
%.o: %.cpp
	@echo Compiling $<...
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

# Clean rule
clean:
	@echo Cleaning up...
	del /Q $(subst /,\,$(TARGET)) $(subst /,\,$(OBJS))

# Force rebuild target
rebuild: clean all

# Aggressive optimization target
aggressive: CXXFLAGS += $(AGGRESSIVE_FLAGS)
aggressive: clean
	@echo Building with aggressive optimizations...
	$(MAKE) all
	@echo Aggressive build complete!

# Print objects for debugging
print-objects:
	@echo "Object files: $(OBJS)"

# Phony targets
.PHONY: all clean rebuild print-objects aggressive
