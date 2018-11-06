#include "torch/data/ctf/ctf_parser.hpp"

#include <cstring>
#include <string>
#include <vector>
#include <cassert>
#include <iostream>
#include <stdexcept>

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

CTFParser::CTFParser(std::string filename) : m_buffer_pos(0)
{
    m_buffer = new char[CTFParser::buffer_size];
    m_reader = new Reader(filename);
    m_dataset = new CTFDataset(filename);
}

CTFParser::~CTFParser()
{
    delete [] m_buffer;
    delete m_reader;
    delete m_dataset;
}

bool CTFParser::GetSequenceId(CTFSequenceID &sequence_id, CTFSequenceID &previous_sequence_id)
{
    // found sequence id string
    std::string id_str;

    // temporary index for iterating over the string buffer
    size_t idx = m_buffer_pos;

    // current char of the buffer
    char c = m_buffer[idx];

    // If sequence doesnt have Sequence ID, uses the Sequence ID from previous sequence
    if (isNamePrefix(c))
    {
        sequence_id = previous_sequence_id;
#ifdef CTF_DEBUG
        std::cout << "Using previous Sequence ID (" << previous_sequence_id << ")" << std::endl;
#endif
        return true;
    }

    // Sequence ID must start with a digit
    if (!isDigit(c))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a Sequence ID (at " << idx << ")" << std::endl;
#endif
        return false;
    }

    // Get all consecutive digits
    while (isDigit(c))
    {
        id_str += c;
        c = m_buffer[++idx];
    }

    // Discard delimiters after the ID
    while (isValueDelimiter(c))
    {
        c = m_buffer[++idx];
    }

    // After Sequence ID, there must be a Name Prefix
    if (!isNamePrefix(c))
    {
#ifdef CTF_DEBUG
        std::cerr << "Invalid CTF file. Missing name delimiter for one of the sequences (at " << idx << ")" << std::endl;
#endif
        return false;
    }

    // Convert string, update buffer state and return the integral ID
#ifdef CTF_DEBUG
    std::cout << "Found Sequence ID: [" << id_str << "] at [" << m_buffer_pos << "]" << std::endl;
#endif
    m_buffer_pos = idx;
    sequence_id = static_cast<CTFSequenceID>(std::stoull(id_str));
    previous_sequence_id = sequence_id;
    return true;
}

bool CTFParser::GetName(std::string &name)
{
    // found CTF nAME string
    std::string name_str;

    // temporary index for iterating over the string buffer
    size_t idx = m_buffer_pos;

    // current char of the buffer
    char c = m_buffer[idx];

    // CTF Name must start with a |
    if (!isNamePrefix(c))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a CTF Name (at" << idx << ")" << std::endl;
#endif
        return false;
    }
    c = m_buffer[++idx];

    // Get all consecutive digits and alpha characters
    while (isDigit(c) || isAlpha(c))
    {
        name_str += c;
        c = m_buffer[++idx];
    }

    // Discard delimiters after the CTF Name
    while (isValueDelimiter(c))
    {
        c = m_buffer[++idx];
    }

    // After CTF Name, there must be a CTF value
    if (!isNumber(c))
    {
#ifdef CTF_DEBUG
        std::cerr << "Invalid CTF file. Unexpected symbol after CTF Name (" << c << " at " << idx << ")" << std::endl;
#endif
        return false;
    }

    // Return the CTF Name
    name = name_str;
#ifdef CTF_DEBUG
    std::cout << "Found CTF Name: [" << name_str << "] at [" << m_buffer_pos << "]" << std::endl;
#endif
    m_buffer_pos = idx;
    return true;
}

bool CTFParser::GetValue(CTFValue &value)
{
    // found CTF Value string
    std::string value_str;
    std::string index_str;

    // temporary index for iterating over the string buffer
    size_t idx = m_buffer_pos;

    // current char of the buffer
    char c = m_buffer[idx];

    // CTF Value must start with a digit or signal
    if (!isNumber(c))
    {
#ifdef CTF_DEBUG
        std::cerr << "Not a CTF Value (" << c << " at " << m_buffer_pos << ")" << std::endl;
#endif
        return false;
    }

    // Get all consecutive digits and decimal point, if any
    // TODO: Should support 1.23e-45 format?
    bool is_float = false;
    bool has_signal = false;
    while (isNumber(c) || isSparseValueDelimiter(c))
    {
        if (isSign(c))
        {
            if (has_signal)
            {
#ifdef CTF_DEBUG
                std::cerr << "Invalid CTF file. CTF value with more than one positive or negative signals (at " << idx << ")" << std::endl;
#endif
                return false;
            }
            has_signal = true;
        }
        if (isDecimalPoint(c))
        {
            if (is_float)
            {
#ifdef CTF_DEBUG
                std::cerr << "Invalid CTF file. CTF value with more than one decimal point (at " << idx << ")" << std::endl;
#endif
                return false;
            }
            is_float = true;
        }
        if (isSparseValueDelimiter(c))
        {
            // TODO: Look for decimal point on index? It will be truncated anyway
            index_str = value_str;
            value_str.clear();
        }
        else
        {
            value_str += c;
        }
        c = m_buffer[++idx];
    }

    // Discard delimiters after the CTF Value
    while (isValueDelimiter(c))
    {
        c = m_buffer[++idx];
    }

    // After CTF Value, there must be another CTF Value or an optional CTF Comment
    if (!isNumber(c) && !isCommentPrefix(c) && !isEOL(c))
    {
#ifdef CTF_DEBUG
        std::cerr << "Invalid CTF file. Unexpected symbol (" << c << ") after CTF Value (at" << idx << ")" << std::endl;
#endif
        return false;
    }

    // Convert string, update buffer state and return the integral ID
    value.type = is_float ? CTFValueType::Double : CTFValueType::Int16;
    value.value = is_float ? static_cast<double>(std::stod(value_str)) : static_cast<long long int>(std::stoll(value_str));
    value.index = index_str.empty() ? SIZE_MAX : static_cast<CTFSequenceID>(std::stoull(index_str));
#ifdef CTF_DEBUG
    std::cout << "Found Value: Value [" << value_str << "] and index [" << index_str << "] at [" << m_buffer_pos << "]" << std::endl;
#endif
    m_buffer_pos = idx;
    return true;
}

bool CTFParser::GetValues(std::vector<CTFValue> &values)
{
    std::vector<CTFValue> temp_values;
    char c = m_buffer[m_buffer_pos];
    while (!isNamePrefix(c) && !isCommentPrefix(c) && !isEOL(c) && (m_buffer_pos != m_reader->FileSize()))
    {
        CTFValue value;
        if (!GetValue(value))
        {
#ifdef CTF_DEBUG
            std::cerr << "Failed to get CTF Value (at " << m_buffer_pos << ")" << std::endl;
#endif
            return false;
        }
        temp_values.push_back(value);
        c = m_buffer[m_buffer_pos];
    }

    // Remove EOL
    while (isEOL(c))
    {
        c = m_buffer[++m_buffer_pos];
    }

    values.insert(values.end(), temp_values.begin(), temp_values.end());
    return true;
}

bool CTFParser::GetSample(CTFSample &sample)
{

    return (GetName(sample.input_name) && GetValues(sample.values));
}

bool CTFParser::GetComment(std::string &comment)
{
    size_t quote_count = 0;
    // found CTF Comment string
    std::string comment_str;

    // temporary index for iterating over the string buffer
    size_t idx = m_buffer_pos;

    // current char of the buffer
    char c = m_buffer[idx];

    // CTF Comment must start with |#
    if (!isCommentPrefix(c))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a CTF Comment (at " << idx << ")" << std::endl;
#endif
        return false;
    }
    c = m_buffer[++idx];
    if (!isCommentSuffix(c))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a CTF Comment (at " << idx << ")" << std::endl;
#endif
        return false;
    }
    c = m_buffer[++idx];
    // Get all consecutive digits and alpha characters
    while (!isEOL(c))
    {
        comment_str += c;
        c = m_buffer[++idx];

        if (isEscapeDelimiter(c))
        {
            ++quote_count;
        }

        if (isNamePrefix(c) && (quote_count % 2 == 0))
        {
            break;
        }
    }

    // Remove EOL
    while (isEOL(c))
    {
        c = m_buffer[++idx];
    }

    // Return the CTF Name
    comment = comment_str;
#ifdef CTF_DEBUG
    std::cout << "Found CTF Comment: [" << comment_str << "] at [" << m_buffer_pos << "]" << std::endl;
#endif
    m_buffer_pos = idx;
    return true;
}

bool CTFParser::LoadSamples()
{
#ifdef CTF_DEBUG
    size_t read_count = 0;
#endif
    CTFSequenceID previous_sequence_id = 0;
    while (m_reader->CanRead())
    {
        m_reader->ReadLine(m_buffer);
        m_buffer_pos = 0;
#ifdef CTF_DEBUG
        std::cout << "Read count: " << ++read_count << std::endl;
#endif
        while (m_buffer_pos < std::strlen(m_buffer))
        {
            CTFComment comment;
            CTFSequenceID sequence_id;
            // There can be an explicit sequence ID at the beginning of the line or the last known is used implicitly
            if (!GetSequenceId(sequence_id, previous_sequence_id))
            {
                // Line doesn't start with a Sequence ID
                if (!GetComment(comment))
                {
                    // Line doesn't start with a comment
                    m_dataset->sequences.clear();
                    return false;
                }
                else
                {
                    // Line starts with a comment
                    // Each sequence has a single comment, so the last comment override the previous ones
                    m_dataset->sequences[sequence_id].sequence_id = sequence_id;
                    if (!comment.empty())
                    {
                        m_dataset->sequences[sequence_id].comment = comment;
                    }
                }
            }

            // After the sequence ID, there can be many samples/comments
            CTFSample sample;
            if (!GetSample(sample))
            {
                if (!GetComment(comment))
                {
#ifdef CTF_DEBUG
                    std::cout << "Neither a CTF Value nor a CTF Comment was found (at " << m_buffer_pos << "). Is it a bad CTF file?" << std::endl;
#endif
                    m_dataset->sequences.clear();
                    return false;
                }
            }
            // Initializes a new sequence on the dataset
            m_dataset->sequences[sequence_id].sequence_id = sequence_id;
            // Appends a new sample to the dataset
            if (!sample.input_name.empty())
            {
                m_dataset->sequences[sequence_id].samples.push_back(sample);
            }
            // Updates the comment for the sequence. Previous comments are overwritten
            if (!comment.empty())
            {
                m_dataset->sequences[sequence_id].comment = comment;
            }
        }
    }

    return true;
}

const CTFDataset &CTFParser::GetDataSet(void) const
{
    return *m_dataset;
}

/*
 * Overriding operator<< for base classes
 */
std::ostream &operator<<(std::ostream &os, const CTFValue &ctf_value)
{
#ifdef CTF_DEBUG
    os << "Value: " << ctf_value.value << ", "
       << "Type: " << ctf_value_type_str[ctf_value.type];
    if (ctf_value.index != SIZE_MAX)
    {
        os << ", Index: " << ctf_value.index;
    }
#else
    if (ctf_value.index != SIZE_MAX)
    {
        os << ctf_value.index << ":";
    }
    os << ctf_value.value << " ";
#endif
    return os;
}

std::ostream &operator<<(std::ostream &os, const CTFSample &ctf_sample)
{
#ifdef CTF_DEBUG
    os << "Input name: " << ctf_sample.input_name << ", "
       << "Values: " << std::endl;
    for (auto it = ctf_sample.values.begin(); it != ctf_sample.values.end(); ++it)
    {
        os << '\t' << "[" << *it << "]" << std::endl;
    }
#else
    os << " |" << ctf_sample.input_name << " ";
    for (auto it = ctf_sample.values.begin(); it != ctf_sample.values.end(); ++it)
    {
        os << *it;
    }
#endif
    return os;
}

std::ostream &operator<<(std::ostream &os, const CTFSequence &ctf_sequence)
{
#ifdef CTF_DEBUG
    os << "Sequence ID: " << ctf_sequence.sequence_id << std::endl;
    if (!ctf_sequence.comment.empty())
    {
        os << "Comment: " << ctf_sequence.comment << std::endl;
    }
    for (auto it = ctf_sequence.samples.begin(); it != ctf_sequence.samples.end(); ++it)
    {
        os << *it;
    }
#else
    os << ctf_sequence.sequence_id;
    for (auto it = ctf_sequence.samples.begin(); it != ctf_sequence.samples.end(); ++it)
    {
        os << *it;
    }
    if (!ctf_sequence.comment.empty())
    {
        os << " |#" << ctf_sequence.comment;
    }
#endif
    return os;
}

std::ostream &operator<<(std::ostream &os, const CTFDataset &ctf_dataset)
{
#ifdef CTF_DEBUG
    os << "Filename: " << ctf_dataset.filename << std::endl;
    for (auto it = ctf_dataset.sequences.begin(); it != ctf_dataset.sequences.end(); ++it)
    {
        os << it->second;
    }
#else
    os << ctf_dataset.filename << std::endl;
    for (auto it = ctf_dataset.sequences.begin(); it != ctf_dataset.sequences.end(); ++it)
    {
        os << it->second << std::endl;
    }
#endif
    return os;
}

void CTFParser::PrintData() const
{
    std::cout << m_dataset->filename << std::endl;
    for (auto sequence : m_dataset->sequences)
    {
        std::cout << sequence.second.sequence_id;
        if (!sequence.second.comment.empty())
        {
            std::cout << " |#" << sequence.second.comment;
        }
        std::cout << std::endl;
        for (auto sample : sequence.second.samples)
        {
            std::cout << " |" << sample.input_name << " ";
            for (auto value : sample.values)
            {
                if (value.index != SIZE_MAX)
                {
                    std::cout << value.index << ":";
                }
                std::cout << value.value << " ";
            }
            std::cout << std::endl;
        }
    }
}

bool CTFValue::operator==(const CTFValue &rhs) const
{
    return (this->index == rhs.index &&
            this->type == rhs.type &&
            this->value == rhs.value);
}

bool CTFSample::operator==(const CTFSample &rhs) const
{
    return (this->input_name == rhs.input_name &&
            std::equal(this->values.begin(),
                       this->values.end(),
                       rhs.values.begin()));
}

bool CTFSequence::operator==(const CTFSequence &rhs) const
{
    return (this->sequence_id == rhs.sequence_id &&
            std::equal(this->samples.begin(),
                       this->samples.end(),
                       rhs.samples.begin()));
}

bool CTFDataset::operator==(const CTFDataset &rhs) const
{
    return (std::equal(this->sequences.begin(),
                       this->sequences.end(),
                       rhs.sequences.begin()));

    return true;
}