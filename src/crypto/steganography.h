#ifndef STEGANOGRAPHY_H
#define STEGANOGRAPHY_H

#include <string>
#include <vector>

// Functions for hiding and extracting data from images
namespace Steganography {
    // Hide binary data in an image file
    bool hideDataInImage(const std::string& imagePath, const std::vector<unsigned char>& data, const std::string& outputPath);
    
    // Extract hidden data from an image file
    std::vector<unsigned char> extractDataFromImage(const std::string& imagePath);
    
    // Create a basic PNG image for storing keys if none exists
    bool createImageIfNeeded(const std::string& imagePath, int width = 512, int height = 512);
}

#endif
