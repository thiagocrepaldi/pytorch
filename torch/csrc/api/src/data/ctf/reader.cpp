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
    size_t len = 0;
    while (m_file.get(buffer[len]))
    {
        if (buffer[len] == '\n' || buffer[len] == '\r' || buffer[len] == '\0') {
            ++len;
            break;
        }
        ++len;
    }
    buffer[len]='\0';
    return len;
}

size_t Reader::FileSize() const
{
    return m_file_size;
}

bool Reader::CanRead()
{
    return (!m_file.eof() && m_file.good() && m_file.tellg() != m_file_size);
}