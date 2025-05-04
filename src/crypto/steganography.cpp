#include "steganography.h"
#include <cstring>
#include <stdexcept>
#include <filesystem>

// STB Image implementation
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

namespace Steganography {

// Create a basic PNG image for storing keys if none exists
bool createImageIfNeeded(const std::string& imagePath, int width, int height) {
    if (std::filesystem::exists(imagePath)) {
        return true; // Image already exists, no need to create
    }
    
    // Create a blank RGBA image
    unsigned char* imgData = new unsigned char[width * height * 4];
    
    // Fill with gradient pattern (to make it look less suspicious)
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            int idx = (y * width + x) * 4;
            imgData[idx] = static_cast<unsigned char>((x * 255) / width);     // R
            imgData[idx+1] = static_cast<unsigned char>((y * 255) / height);  // G
            imgData[idx+2] = static_cast<unsigned char>(((x+y) * 127) / (width+height)); // B
            imgData[idx+3] = 255; // Alpha (fully opaque)
        }
    }
    
    // Save the image
    int result = stbi_write_png(imagePath.c_str(), width, height, 4, imgData, width * 4);
    delete[] imgData;
    
    return result != 0;
}

// Hide data in an image using LSB steganography
bool hideDataInImage(const std::string& imagePath, const std::vector<unsigned char>& data, const std::string& outputPath) {
    // Create image if it doesn't exist
    if (!std::filesystem::exists(imagePath)) {
        if (!createImageIfNeeded(imagePath)) {
            return false;
        }
    }
    
    // Load the image
    int width, height, channels;
    unsigned char* img = stbi_load(imagePath.c_str(), &width, &height, &channels, 0);
    
    if (!img) {
        return false;
    }
    
    // Calculate how many bytes we can hide (using 1 bit per channel)
    size_t maxBytes = (width * height * channels) / 8;
    
    // Check if image is big enough
    if (data.size() + 4 > maxBytes) {
        stbi_image_free(img);
        return false;
    }
    
    // Store data size in the first 4 bytes (32 bits)
    uint32_t dataSize = static_cast<uint32_t>(data.size());
    for (int i = 0; i < 32; ++i) {
        uint8_t bit = (dataSize >> i) & 1;
        int bytePos = i / channels;
        int channel = i % channels;
        
        // Clear LSB and set it to the bit
        img[bytePos * channels + channel] = (img[bytePos * channels + channel] & 0xFE) | bit;
    }
    
    // Hide data bytes
    for (size_t i = 0; i < data.size(); ++i) {
        for (int j = 0; j < 8; ++j) {
            uint8_t bit = (data[i] >> j) & 1;
            int bytePos = (i * 8 + j + 32) / channels;
            int channel = (i * 8 + j + 32) % channels;
            
            // Clear LSB and set it to the bit
            img[bytePos * channels + channel] = (img[bytePos * channels + channel] & 0xFE) | bit;
        }
    }
    
    // Save the modified image
    int result = stbi_write_png(outputPath.c_str(), width, height, channels, img, width * channels);
    stbi_image_free(img);
    
    return result != 0;
}

// Extract data from an image using LSB steganography
std::vector<unsigned char> extractDataFromImage(const std::string& imagePath) {
    if (!std::filesystem::exists(imagePath)) {
        return {};
    }
    
    int width, height, channels;
    unsigned char* img = stbi_load(imagePath.c_str(), &width, &height, &channels, 0);
    
    if (!img) {
        return {};
    }
    
    // Extract data size from the first 4 bytes (32 bits)
    uint32_t dataSize = 0;
    for (int i = 0; i < 32; ++i) {
        int bytePos = i / channels;
        int channel = i % channels;
        
        // Get the LSB
        uint8_t bit = img[bytePos * channels + channel] & 1;
        dataSize |= (bit << i);
    }
    
    // Check if data size is reasonable
    size_t maxBytes = (width * height * channels) / 8 - 4;
    if (dataSize > maxBytes || dataSize == 0) {
        stbi_image_free(img);
        return {};
    }
    
    // Extract data
    std::vector<unsigned char> data(dataSize, 0);
    for (size_t i = 0; i < dataSize; ++i) {
        for (int j = 0; j < 8; ++j) {
            int bytePos = (i * 8 + j + 32) / channels;
            int channel = (i * 8 + j + 32) % channels;
            
            // Get the LSB
            uint8_t bit = img[bytePos * channels + channel] & 1;
            if (bit) {
                data[i] |= (1 << j);
            }
        }
    }
    
    stbi_image_free(img);
    return data;
}

} // namespace Steganography
