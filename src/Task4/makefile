# Makefile for compiling securechat

# Compiler settings - Can be customized.
CXX = g++
CXXFLAGS = -Wall -std=c++11
LDFLAGS = -lssl -lcrypto -pthread

# Source and object files
SOURCES = secure_chat_active_interceptor.cpp
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = securechat

# Default target
all: $(TARGET)

# Rule for linking the final application
$(TARGET): $(OBJECTS)
    $(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)

# Rule for compiling source files to object files
%.o: %.cpp
    $(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up generated files
clean:
    rm -f $(TARGET) $(OBJECTS)


