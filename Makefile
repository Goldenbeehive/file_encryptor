# File Encryptor Makefile for Windows with GCC

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic
INCLUDES = -I./include -I./src

# Output executable name
TARGET = file_encryptor.exe

# Source files
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

# Print objects for debugging
print-objects:
	@echo "Object files: $(OBJS)"

# Phony targets
.PHONY: all clean rebuild print-objects
