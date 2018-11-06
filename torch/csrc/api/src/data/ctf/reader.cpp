#include "torch/data/ctf/reader.hpp"

#include <cstring>
#include <cassert>
#include <iostream>

/*
 * Reader class for CTF
 * 
 * RAII pattern was used for file descriptor
 */

Reader::~Reader()
{
    if (m_file.is_open())
    {
        m_file.close();
    }
}

Reader::Reader(const std::string &filename) : m_filename(filename)
{
    m_file.open (m_filename, std::ios::in);
    if (!m_file.is_open()) {
        throw "Reader could not open the specified file!";
    }
    // Get file length
    m_file.seekg (0, std::ios::end);
    m_file_size = m_file.tellg();
    m_file.seekg (0, std::ios::beg);
}

size_t
Reader::ReadLine(char *(&buffer))
{
    std::string line;
    std::getline (m_file, line);
    std::memset(buffer, 0, strlen(buffer)); // TODO: Should we assume buffer is clean already?
    std::strncpy(buffer, line.c_str(), line.size());
    if (!line.empty()) {
        // Last line doesn't get a \n
        buffer[line.size()] = '\n';
    }
    return (line.size()+1);
}

size_t Reader::FileSize() const
{
    return m_file_size;
}

bool Reader::CanRead() const
{
    return !m_file.eof();
}