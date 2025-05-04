# File Encryptor Makefile for Windows with GCC

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic
INCLUDES = -I./include -I./src

# Windows libraries for GUI application
WIN_LIBS = -lcomctl32 -luser32 -lgdi32

# Aggressive compilation flags
AGGRESSIVE_FLAGS = -O3 -march=native -flto -ffast-math -funroll-loops -fomit-frame-pointer

# Output executable name
TARGET = file_encryptor.exe
GUI_TARGET = file_encryptor_gui.exe

# Source files - separate CLI and GUI sources to avoid collision
COMMON_SRCS = $(wildcard src/crypto/*.cpp) $(wildcard src/io/*.cpp) $(wildcard src/keys/*.cpp) src/file_encryptor.cpp src/constants.cpp
CLI_SRCS = $(COMMON_SRCS) src/main.cpp $(wildcard src/ui/cli.cpp)
GUI_SRCS = $(COMMON_SRCS) src/main_gui.cpp $(wildcard src/ui/gui.cpp)

# Object files
CLI_OBJS = $(CLI_SRCS:.cpp=.o)
GUI_OBJS = $(GUI_SRCS:.cpp=.o)

# Main target - default is CLI version
all: cli

# CLI version
cli: $(TARGET)

# GUI version (our main focus)
gui: $(GUI_TARGET)

# Link CLI version
$(TARGET): $(CLI_OBJS)
	@echo Linking $(TARGET)...
	$(CXX) -o $@ $^ $(CXXFLAGS)
	@echo CLI Build complete!

# Link GUI version with Windows libraries and GUI subsystem
$(GUI_TARGET): $(GUI_OBJS)
	@echo Linking $(GUI_TARGET)...
	$(CXX) -o $@ $^ $(CXXFLAGS) $(WIN_LIBS) -mwindows
	@echo GUI Build complete!

# Compile rule
%.o: %.cpp
	@echo Compiling $<...
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

# Clean rule
clean:
	@echo Cleaning up...
	del /Q $(subst /,\,$(TARGET)) $(subst /,\,$(GUI_TARGET)) $(subst /,\,$(CLI_OBJS)) $(subst /,\,$(GUI_OBJS))

# Force rebuild targets
rebuild-cli: clean cli
rebuild-gui: clean gui

# Aggressive optimization targets
aggressive-cli: CXXFLAGS += $(AGGRESSIVE_FLAGS)
aggressive-cli: clean
	@echo Building CLI with aggressive optimizations...
	$(MAKE) cli
	@echo CLI Aggressive build complete!

aggressive-gui: CXXFLAGS += $(AGGRESSIVE_FLAGS)
aggressive-gui: clean
	@echo Building GUI with aggressive optimizations...
	$(MAKE) gui
	@echo GUI Aggressive build complete!

# Default aggressive build is now GUI (what we want)
aggressive: aggressive-gui

# Phony targets
.PHONY: all cli gui clean rebuild-cli rebuild-gui aggressive-cli aggressive-gui aggressive
