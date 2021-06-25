#include <iostream>
#include <fstream>
#include <filesystem>
#include <optional>
#include <sstream>
#include <vector>
#include <cstring>
#include <cmath>
#include <algorithm>

std::uint32_t readLE32(const std::vector<std::uint8_t> block, size_t offset)
{
    return block[offset + 0] + (block[offset + 1] << 8) + (block[offset + 2] << 16) + (block[offset + 3] << 24);
}

std::optional<std::string> getPathFromPDB(const std::filesystem::path &file)
{
    std::ifstream stream(file, std::ios::binary);
    std::vector<std::uint8_t> buffer(256);
    stream.read(reinterpret_cast<char *>(buffer.data()), 256);

    const char *const header = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44S\0\0\0";
    if (memcmp(buffer.data(), header, 32) != 0)
        return std::nullopt;

    const auto pageSize = readLE32(buffer, 32);
    const auto allocTablePointer = readLE32(buffer, 36);
    const auto numberOfFilePages = readLE32(buffer, 40);
    const auto rootStreamSize = readLE32(buffer, 44);
    const auto reserved = readLE32(buffer, 48);
    const auto pageNumberOfRootStreamPageNumberList = readLE32(buffer, 52);

    // Go to page with the addresses of the root pages
    buffer.resize(pageSize);
    stream.seekg(pageSize * pageNumberOfRootStreamPageNumberList, std::ios::beg);
    stream.read(reinterpret_cast<char *>(buffer.data()), pageSize);

    std::vector<size_t> rootPageOffsets((size_t)std::ceil((double)rootStreamSize / pageSize));
    for (size_t idx = 0; idx < rootPageOffsets.size(); ++idx)
        rootPageOffsets[idx] = pageSize * readLE32(buffer, idx * 4);

    stream.seekg(rootPageOffsets[0], std::ios::beg);
    stream.read(reinterpret_cast<char *>(buffer.data()), pageSize);

    // read the root page first we get the number of streams
    const auto streamCount = readLE32(buffer, 0);

    // then we read the size of the first stream (the only one we're interested in)
    const auto stream0Size = readLE32(buffer, 4);
    const auto stream1Size = readLE32(buffer, 8);

    // now we need to determine on what page the actual pointer to stream0 is stored
    const auto stream1PointersOffset = 4 + (4 * streamCount) + (4 * (size_t)(std::ceil((double)stream0Size / pageSize)));
    const auto pageWithStream1Pointers = stream1PointersOffset / pageSize;
    if (pageWithStream1Pointers != 0)
    {
        stream.seekg(rootPageOffsets[pageWithStream1Pointers], std::ios::beg);
        stream.read(reinterpret_cast<char *>(buffer.data()), pageSize);
    }

    const auto firstPageWithStream1Data = readLE32(buffer, stream1PointersOffset - (pageWithStream1Pointers * pageSize));

    stream.seekg(firstPageWithStream1Data * pageSize, std::ios::beg);
    stream.read(reinterpret_cast<char *>(buffer.data()), 256);

    std::stringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0');

    // read and output the guid
    const std::vector<uint8_t> byteOrder{15, 14, 13, 12, 17, 16, 19, 18, 20, 21, 22, 23, 24, 25, 26, 27};
    std::for_each(byteOrder.begin(), byteOrder.end(), [&](auto byteIdx)
                  { ss << std::setw(2) << (int)buffer[byteIdx]; });

    // microsoft SymStore has the sizeOfImage with lowercase hex?! strange conventions
    const auto ageStart = 8;
    ss.unsetf(std::ios_base::uppercase);
    const auto age = readLE32(buffer, 8);
    ss << age;

    return ss.str();
}

std::optional<std::string> getPathFromEXE(const std::filesystem::path &file)
{
    std::ifstream stream(file, std::ios::binary);
    std::vector<std::uint8_t> buffer(256);
    stream.read(reinterpret_cast<char *>(buffer.data()), 64);

    // Check header
    if (buffer[0] != 'M' || buffer[1] != 'Z')
        return std::nullopt;

    // Read offset to PE header
    const auto PEoffset = readLE32(buffer, 60);
    stream.seekg(PEoffset, std::ios::beg);
    stream.read(reinterpret_cast<char *>(buffer.data()), 256);
    if (buffer[0] != 'P' || buffer[1] != 'E' || buffer[2] != 0x0 || buffer[3] != 0x0)
        return std::nullopt;

    std::stringstream ss;
    ss << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << (int)buffer[11]
       << std::setw(2) << (int)buffer[10] << std::setw(2) << (int)buffer[9] << std::setw(2) << (int)buffer[8];

    // move to the optional header
    uint32_t sizeOfImageStart = 24;
    if (buffer[24] == 0x0B && buffer[25] == 0x02) // PE64
    {
        sizeOfImageStart += 56;
    }
    else if (buffer[24] == 0x0B && buffer[25] == 0x01) // PE32
    {
        sizeOfImageStart += 56;
    }
    else
        return std::nullopt;

    // microsoft SymStore has the sizeOfImage with lowercase hex?! strange conventions
    ss.unsetf(std::ios_base::uppercase);
    const auto sizeOfImage = readLE32(buffer, sizeOfImageStart);
    ss << sizeOfImage;

    return ss.str();
}

int main(int argc, char const *argv[])
{
    if (argc != 2)
    {
        std::cerr << "SymbolPath get path info for the symbol server for a .exe,.dll or .pdb file\n"
                  << argv[0] << " <path to file>\n";
        return 1;
    }

    std::filesystem::path file{argv[1]};

    if (!std::filesystem::exists(file))
    {
        std::cerr << "File does not exist!\n";
        return 1;
    }

    std::optional<std::string> path;
    if (file.extension() == ".pdb")
    {
        path = getPathFromPDB(file);
    }
    else
    {
        path = getPathFromEXE(file);
    }

    if (path)
        std::cout << (*path) << "\n";
    else
    {
        std::cerr << "Invalid binary format.\n";
        return 1;
    }

    return 0;
}
