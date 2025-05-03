#include "file_handler.h"
#include <fstream>
#include <stdexcept>
#include <iostream>

bool readFromFile(const std::string& filePath, std::string& data) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) {
        std::cerr << "Error: Could not open file for reading: " << filePath << std::endl;
        return false;
    }
    
    data = std::string((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    return true;
}

bool writeToFile(const std::string& filePath, const std::string& data) {
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile) {
        std::cerr << "Error: Could not open file for writing: " << filePath << std::endl;
        return false;
    }
    
    outFile.write(data.c_str(), data.size());
    outFile.close();
    return true;
}

std::string readFile(const std::string& filePath) {
    std::string data;
    if (!readFromFile(filePath, data)) {
        throw std::runtime_error("Failed to read file: " + filePath);
    }
    return data;
}

void writeFile(const std::string& filePath, const std::string& data) {
    if (!writeToFile(filePath, data)) {
        throw std::runtime_error("Failed to write file: " + filePath);
    }
}

std::vector<unsigned char> readBinaryFile(const std::string& filePath) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Could not open file for reading: " + filePath);
    }
    
    inFile.seekg(0, std::ios::end);
    size_t fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);
    
    std::vector<unsigned char> buffer(fileSize);
    inFile.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    inFile.close();
    
    return buffer;
}

void writeBinaryFile(const std::string& filePath, const std::vector<unsigned char>& data) {
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Could not open file for writing: " + filePath);
    }
    
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
    outFile.close();
}