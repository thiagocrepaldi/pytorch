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
    m_reader = std::make_shared<Reader>(filename);
    m_dataset = std::make_shared<CTFDataset>();
}

CTFParser::~CTFParser()
{
    delete[] m_buffer;
}

bool CTFParser::GetSequenceId(CTFSequenceID &sequence_id)
{
    size_t runner = m_buffer_pos;

    // Sequence ID must start with a digit
    if (!isDigit(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a Sequence ID at index " << runner << std::endl;
#endif
        return false;
    }

    // Get all consecutive digits
    while (isDigit(m_buffer[runner]))
    {
        ++runner;
    }
    // Store the final index of the sequence id string
    size_t end_seq_id = runner;

    // Discard delimiters after the ID
    while (isValueDelimiter(m_buffer[runner]))
    {
        ++runner;
    }

    // After Sequence ID, there must be a '|'
    if (!isNamePrefix(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cerr << "Missing name delimiter for one of the sequences at index " << runner << std::endl;
#endif
        return false;
    }

    // Convert string, update buffer state and return the integral ID
    m_buffer_pos = runner;
    m_buffer[end_seq_id] = '\0';
    sequence_id = static_cast<CTFSequenceID>(std::stoull(m_buffer));
#ifdef CTF_DEBUG
    std::cout << "Found Sequence ID '" << sequence_id << "' at index " << m_buffer_pos << std::endl;
#endif
    return true;
}

bool CTFParser::GetName(std::string &name)
{
    // temporary index for iterating over the string buffer
    size_t runner = m_buffer_pos;
    size_t beg_name, end_name;

    // CTF Name must start with a |
    if (!isNamePrefix(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a CTF Name at index " << runner << std::endl;
#endif
        return false;
    }
    beg_name=++runner;

    // Get all consecutive digits and alpha characters
    while (isDigit(m_buffer[runner]) || isAlpha(m_buffer[runner]))
    {
        ++runner;
    }
    end_name = runner;

    // Discard delimiters after the CTF Name
    while (isValueDelimiter(m_buffer[runner]))
    {
        ++runner;
    }

    // After CTF Name, there must be a CTF value
    if (!isNumber(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cerr << "Unexpected symbol '" << m_buffer[runner] << "' after CTF Name at index " << runner << std::endl;
#endif
        return false;
    }

    // Return the CTF Name
    name = std::string(m_buffer+beg_name, end_name-beg_name);
#ifdef CTF_DEBUG
    std::cout << "Found CTF Name '" << name << "' at index " << m_buffer_pos << std::endl;
#endif
    m_buffer_pos = runner;
    return true;
}

// #if 0
bool CTFParser::GetValue(CTFValue &value)
{
    // temporary index for iterating over the string buffer
    size_t runner = m_buffer_pos;

    size_t beg_index = SIZE_MAX, end_index = SIZE_MAX;
    size_t beg_value = runner, end_value = runner;

    // CTF Value must start with a digit or signal
    if (!isNumber(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cerr << "Unexpected symbol '" << m_buffer[runner] << "' at index " << runner << std::endl;
#endif
        return false;
    }
    beg_value = runner;

    // Get all consecutive digits and decimal point, if any
    // TODO: Should support 1.23e-45 format?
    bool is_float = false;
    bool has_signal = false;
    while (isNumber(m_buffer[runner]) || isSparseValueDelimiter(m_buffer[runner]))
    {
        if (isSign(m_buffer[runner]))
        {
            if (has_signal)
            {
#ifdef CTF_DEBUG
                std::cerr << "Invalid CTF Value. CTF value with more than one positive or negative sign at index " << runner << std::endl;
#endif
                return false;
            }
            has_signal = true;
        }
        if (isDecimalPoint(m_buffer[runner]))
        {
            if (is_float)
            {
#ifdef CTF_DEBUG
                std::cerr << "Invalid CTF Value. CTF value with more than one decimal point at index " << runner << std::endl;
#endif
                return false;
            }
            is_float = true;
        }
        if (isSparseValueDelimiter(m_buffer[runner]))
        {
            // TODO: Look for decimal point on index? It will be truncated anyway
            beg_index = beg_value;
            end_index = runner;
            beg_value = end_index+1;
        }
        ++runner;
    }
    end_value = runner;
    if (!isEOL(m_buffer[end_value])) {
        m_buffer[runner++] = '\0';
    }
    end_value = runner;

    // Discard delimiters after the CTF Value
    while (isValueDelimiter(m_buffer[runner]))
    {
        ++runner;
    }

    // After CTF Value, there must be another CTF Value or an optional CTF Comment
    if (!isNumber(m_buffer[runner]) && !isCommentPrefix(m_buffer[runner]) && !isEOL(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cerr << "Unexpected symbol '" << m_buffer[runner] << "' after CTF Value at index " << runner << std::endl;
#endif
        return false;
    }

    // Convert string, update buffer state and return the integral ID
    value.type = is_float ? CTFValueType::Double : CTFValueType::Int16;
    if (beg_index == SIZE_MAX) {
        value.index = SIZE_MAX;
    } else {
        m_buffer[end_index] = '\0';
        value.index = static_cast<CTFSequenceID>(std::stoull(m_buffer+beg_index));
    }
    value.value = is_float ? static_cast<double>(std::stod(m_buffer+beg_value)) : static_cast<long long int>(std::stoll(m_buffer+beg_value));
#ifdef CTF_DEBUG
    std::cout << "Found CTF Value '" << value.value << "', CTF Index '" << value.index << "'  and CTF Type '" << value.type << "' at index " << m_buffer_pos << std::endl;
#endif
    m_buffer_pos = runner;
    return true;
}

bool CTFParser::GetValues(std::vector<CTFValue> &values)
{
    std::vector<CTFValue> temp_values;
    while (!isNamePrefix(m_buffer[m_buffer_pos]) && !isCommentPrefix(m_buffer[m_buffer_pos]) && !isEOL(m_buffer[m_buffer_pos]) && (m_buffer_pos != m_reader->FileSize()))
    {
        CTFValue value;
        if (!GetValue(value))
        {
#ifdef CTF_DEBUG
            std::cerr << "Failed to get CTF Value at index " << m_buffer_pos << std::endl;
#endif
            return false;
        }
        temp_values.push_back(value);
    }

    // Remove EOL
    while (isEOL(m_buffer[m_buffer_pos]))
    {
        ++m_buffer_pos;
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

    // temporary index for iterating over the string buffer
    size_t runner = m_buffer_pos;
    size_t beg_comment, end_comment;

    // CTF Comment must start with |#
    if (!isCommentPrefix(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a CTF Comment at index " << runner << std::endl;
#endif
        return false;
    }
    ++runner;
    if (!isCommentSuffix(m_buffer[runner]))
    {
#ifdef CTF_DEBUG
        std::cout << "Not a CTF Comment at index " << runner << std::endl;
#endif
        return false;
    }
    beg_comment = ++runner;
    // Get all consecutive digits and alpha characters
    while (!isEOL(m_buffer[runner]))
    {
        ++runner;

        if (isEscapeDelimiter(m_buffer[runner]))
        {
            ++quote_count;
        }

        if (isNamePrefix(m_buffer[runner]) && (quote_count % 2 == 0))
        {
            break;
        }
    }
    end_comment = runner;
    if (!isEOL(m_buffer[end_comment])) {
        m_buffer[end_comment-1] = '\0';
    }

    // Remove EOL
    while (isEOL(m_buffer[runner]))
    {
        ++runner;
    }

    // Return the CTF Name
    comment = std::string(m_buffer+beg_comment, end_comment-beg_comment);
#ifdef CTF_DEBUG
    std::cout << "Found CTF Comment '" << comment << "' at index " << m_buffer_pos << std::endl;
#endif
    m_buffer_pos = runner;
    return true;
}

void CTFParser::LoadSamples()
{
#ifdef CTF_DEBUG
    size_t read_count = 0;
#endif
    CTFSequenceID sequence_id;
    CTFSequenceID previous_sequence_id = 0;
    bool has_initial_sequence_id = false;
    while (m_reader->CanRead())
    {
        size_t len = m_reader->ReadLine(m_buffer);
#ifdef CTF_DEBUG
        std::cout << "Read file count: " << ++read_count << " (" << len << " bytes)" << std::endl;
#endif
        m_buffer_pos = 0;

        // There can be an explicit sequence ID at the beginning of the line or the last known is used implicitly
        if (!GetSequenceId(sequence_id))
        {
            if (has_initial_sequence_id)
            {
                sequence_id = previous_sequence_id;
#ifdef CTF_DEBUG
                std::cout << "Using previous Sequence ID (" << previous_sequence_id << ")" << std::endl;
#endif
            }
            else
            {
                sequence_id = ++previous_sequence_id;
#ifdef CTF_DEBUG
                std::cout << "Incrementing previous Sequence ID (" << previous_sequence_id << ")" << std::endl;
#endif
            }
        }
        else
        {
            has_initial_sequence_id = true;
        }
        previous_sequence_id = sequence_id;

        while (m_buffer_pos < len)
        {
            // After the sequence ID, there can be many samples/comments
            CTFSample sample;
            CTFComment comment;
            if (!GetSample(sample))
            {
                if (!GetComment(comment))
                {
                    std::string error_msg("Invalid CTF File. Neither a CTF Value nor a CTF Comment was found at index " + m_buffer_pos);
#ifdef CTF_DEBUG
                    std::cout << error_msg << m_buffer_pos << std::endl;
#endif
                    m_dataset->sequences.clear();
                    throw error_msg;
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
    for (auto it = ctf_dataset.sequences.begin(); it != ctf_dataset.sequences.end(); ++it)
    {
        os << it->second;
    }
#else
    for (auto it = ctf_dataset.sequences.begin(); it != ctf_dataset.sequences.end(); ++it)
    {
        os << it->second << std::endl;
    }
#endif
    return os;
}

void CTFParser::PrintData() const
{
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
