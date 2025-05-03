#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <string>
#include <vector>

std::string readFile(const std::string& filePath);
void writeFile(const std::string& filePath, const std::string& data);
std::vector<unsigned char> readBinaryFile(const std::string& filePath);
void writeBinaryFile(const std::string& filePath, const std::vector<unsigned char>& data);

#endif