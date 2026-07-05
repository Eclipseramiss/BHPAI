CXX = g++
CC = gcc

CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -I. -ICore/Decompile -ICore/scanner -Ifuzzy -I"C:/msys64/mingw64/include"

LIBS = -lcapstone -lssl -lcrypto -lwintrust -lws2_32

TARGET = pe_analyzer.exe

CPP_SRCS = Core/scanner/pe_analyzer.cpp Core/scanner/pe_features.cpp Core/scanner/pe_opcode_ngram.cpp Core/scanner/StringEx.cpp \
           Core/scanner/YaraGen.cpp Core/scanner/hash_utils.cpp Core/scanner/detect.cpp Core/Decompile/Disassembler.cpp Core/Decompile/PeParser.cpp Core/scanner/opcode_tfidf.cpp

C_SRCS = fuzzy/fuzzyhash.c

OBJS = $(CPP_SRCS:.cpp=.o) $(C_SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS) -static-libgcc -static-libstdc++

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CXXFLAGS) -c $< -o $@

clean:
	del *.o $(TARGET) 2>nul || rm -f *.o $(TARGET)