#pragma once

#include "torch/data/ctf/reader.hpp"
#include "torch/csrc/utils/disallow_copy.h"

#include <map>
#include <vector>
#include <cassert>
#include <iostream>
#include <memory>
#include <ostream>
#include <stdint.h>

/*
 * CTF general format
 * [Sequence_Id](Sample or Comment)+
 *   where
 *          sequence_Id=(empty|[0-9]+)
 *          Sample=|Input_Name (Value )*
 *          Comment=|# some content
 *
 * 100 |a 1 2 3 |b 100 200
 * 100 |a 4 5 6 |b 101 201
 * 100 |b 102983 14532 |a 7 8 9
 * 100 |a 7 8 9
 * 200 |b 300 400 |a 10 20 30
 * 333 |b 500 100
 * 333 |b 600 -900
 * 400 |a 1 2 3 |b 100 200
 * |a 4 5 6 |b 101 201
 * |a 4 5 6 |b 101 201
 * 500 |a 1 2 3 |b 100 200
 */

/* General use string parsing helpers */
static const char SPACE_CHAR = ' ';
static const char TAB_CHAR = '\t';
static const char NAME_PREFIX = '|';
static const char INDEX_DELIMITER = ':';
static const char ESCAPE_SYMBOL = '#';

inline bool isNamePrefix(const char &c)
{
    return (c == NAME_PREFIX);
}

inline bool isCommentPrefix(const char &c)
{
    return (isNamePrefix(c));
}

inline bool isCommentSuffix(const char &c)
{
    return (c == '#');
}

inline bool isDecimalPoint(const char &c)
{
    return (c == '.');
}

inline bool isSparseValueDelimiter(const char &c)
{
    return (c == ':');
}

inline bool isDigit(const char &c)
{
    return (c >= '0' && c <= '9');
}

inline bool isAlpha(const char &c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

inline bool isSign(const char &c)
{
    return c == '+' || c == '-';
}

inline bool isNumber(const char &c)
{
    return (isDigit(c) || isDecimalPoint(c) || isSign(c));
}

inline bool isPrintable(const char &c)
{
    return c >= SPACE_CHAR;
}

inline bool isNonPrintable(const char &c)
{
    return !isPrintable(c);
}

inline bool isValueDelimiter(const char &c)
{
    return c == SPACE_CHAR || c == TAB_CHAR;
}

inline bool isEOL(const char &c)
{
    return (c == '\r' || c == '\n');
}

inline bool isEscapeDelimiter(const char &c)
{
    return (c == '\'' || c == '"');
}

inline bool isColumnDelimiter(const char &c)
{
    return isValueDelimiter(c) || (isNonPrintable(c) && !isEOL(c));
}

/* CTF-specific types */

enum CTFValueType
{
    Unknown = 0x0,
    Float = 0x1,
    Double = 0x2,
    Float16 = 0x3,
    Int8 = 0x4,
    Int16 = 0x5
};
static const std::string ctf_value_type_str[] = {"Unknown", "Float", "Double", "Float16", "Int8", "Int16"};

typedef size_t CTFSequenceID;
typedef std::string CTFName;
typedef std::string CTFComment;

struct CTFValue
{
    explicit CTFValue() : type(CTFValueType::Unknown),
                          value(0),
                          index(SIZE_MAX){};
    explicit CTFValue(CTFValueType type, double value, size_t index = SIZE_MAX) : type(type),
                                                                                  value(value),
                                                                                  index(index) {}

    CTFValueType type;
    double value;
    size_t index;
    bool operator==(const CTFValue &rhs) const;
};

struct CTFSample
{
    explicit CTFSample() : input_name(std::string()),
                           values(std::vector<CTFValue>()) {}
    explicit CTFSample(std::string input_name) : input_name(input_name),
                                                 values(std::vector<CTFValue>()) {}
    explicit CTFSample(std::string input_name, std::vector<CTFValue> values) : input_name(input_name),
                                                                               values(values) {}

    std::string input_name;
    std::vector<CTFValue> values;
    bool operator==(const CTFSample &rhs) const;
};

struct CTFSequence
{
    explicit CTFSequence() : sequence_id(0),
                             samples(std::vector<CTFSample>()),
                             comment(std::string()) {}
    explicit CTFSequence(CTFSequenceID sequence_id, std::string comment = std::string()) : sequence_id(sequence_id),
                                                                                           comment(comment) {}
    explicit CTFSequence(CTFSequenceID sequence_id, std::vector<CTFSample> samples, std::string comment = std::string()) : sequence_id(sequence_id),
                                                                                                                           samples(samples),
                                                                                                                           comment(comment) {}
    CTFSequenceID sequence_id;
    std::vector<struct CTFSample> samples;
    CTFComment comment;
    bool operator==(const CTFSequence &rhs) const;
};

struct CTFDataset
{
    explicit CTFDataset() : sequences(std::map<CTFSequenceID, CTFSequence>()) {}
    explicit CTFDataset(std::map<CTFSequenceID, CTFSequence> sequences) : sequences(sequences) {}
    std::map<CTFSequenceID, CTFSequence> sequences;
    bool operator==(const CTFDataset &rhs) const;
};

std::ostream &operator<<(std::ostream &os, const CTFValue &ctf_value);
std::ostream &operator<<(std::ostream &os, const CTFSample &ctf_sample);
std::ostream &operator<<(std::ostream &os, const CTFSequence &ctf_sequence);
std::ostream &operator<<(std::ostream &os, const CTFDataset &ctf_dataset);

class CTFParser
{
  public:
    explicit CTFParser(std::string filename);
    virtual ~CTFParser();

    void LoadSamples();
    void PrintData() const;
    const CTFDataset &GetDataSet() const;

  private:
    CTFParser() = delete;
    TH_DISALLOW_COPY_AND_ASSIGN(CTFParser);

    bool GetSequenceId(CTFSequenceID &sequence_id);
    bool GetName(std::string &name);
    bool GetValue(CTFValue &value);
    bool GetComment(std::string &comment);
    bool GetValues(std::vector<CTFValue> &value);
    bool GetSample(CTFSample &sample);

    static const size_t buffer_size = 1024*1024; // buffer_size must be big enough to fit a really long line on the CTF file
    char *m_buffer; // buffer for temporarily holding a CTF line during parsing
    size_t m_buffer_pos; // parsing position of m_buffer
    std::shared_ptr<CTFDataset> m_dataset; // dataset holding all parsed entries
    std::shared_ptr<Reader> m_reader; // resposible for reading the CTF file
};
