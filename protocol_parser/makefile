CXX = g++
CXXFLAGS = -std=c++17 -Wall -Iheader

SRC = $(wildcard parsers/*.cpp) modbus_parser.cpp

OBJ = $(SRC:.cpp=.o)
TARGET = modbus_parser

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ)

clean:
	rm -f $(OBJ) $(TARGET)
