#pragma once

#include "torch/csrc/utils/disallow_copy.h"

#include <iostream>
#include <fstream>

class Reader
{
public:
  virtual ~Reader();
  explicit Reader(const std::string &filename);

  size_t ReadLine(char *(&buffer));
  size_t FileSize() const;
  bool CanRead() const;

private:
  std::string m_filename;
  std::size_t m_file_size;
  std::ifstream m_file;

  Reader() = delete;
  TH_DISALLOW_COPY_AND_ASSIGN(Reader);
};