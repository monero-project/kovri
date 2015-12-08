#ifndef _HTTP_H__
#define _HTTP_H__

#include <string>
#include <map>
#include <sstream>
#include <iostream>
#include <regex>
#include <fstream>

#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Log.h"
#include "Reseed.h"
#include "Filesystem.h"

namespace i2p {
namespace util {
namespace http {

/**
 * @return the result of the download, or an empty string if it fails
 */
std::string HttpsDownload(const std::string& address);

/**
 * @class URI provides functionality for parsing URIs
 */
class URI {
    /**
     * The code for ParseURI() was originally copied/pasted from
     * https://stackoverflow.com/questions/2616011/easy-way-to-parse-a-url-in-c-cross-platform
     *
     * See cpp-netlib for a better URI parsing implementation with Boost.
     *
     * Note: fragments are not parsed by this function (if they should
     * ever be needed in the future).
     *
     * @param string URI
     */
    void ParseURI(const std::string& uri);
    public:
        std::string m_Protocol, m_Host, m_Path, m_PortString, m_Query;
        int m_Port;
	/**
         * Parse a URI given as a string.
         */
	URI(const std::string& uri);
};

/**
 * Header for HTTPS requests.
 * @return a string of the complete header
 */
std::string HttpHeader(const std::string& path, const std::string& host, const std::string& version);

/**
 * @return the content of the given HTTP stream without headers
 */
std::string GetHttpContent(std::istream& response);

/**
 * Merge chunks of an HTTP response.
 */
void MergeChunkedResponse(std::istream& response, std::ostream& merged);

class Request {
    void ParseRequestLine(const std::string& line);
    void ParseHeaderLine(const std::string& line);
    void ParseHeader(std::stringstream& ss);
    void SetIsComplete();

    std::string m_HeaderSection, m_Method, m_URI, m_Host, m_Content;
    int m_Port;
    std::map<std::string, std::string> m_Headers;
    bool m_HasData, m_HasHeader, m_IsComplete;

public:
    Request() = default;
    Request(const std::string& data);

    std::string GetMethod() const;
    std::string GetUri() const;
    std::string GetHost() const;
    int GetPort() const;

    /**
     * @throw std::out_of_range if no such header exists
     */
    std::string GetHeader(const std::string& name) const;
    std::string GetContent() const;

    bool HasData() const;
    bool IsComplete() const;
    void Clear();
    void Update(const std::string& data);
};

class Response {
    int status;
    std::string content;
    std::map<std::string, std::string> headers;

public:
    Response() = default;
    Response(int status, const std::string& content = "");

    /**
     * @note overrides existing header values with the same name
     */
    void SetHeader(const std::string& name, const std::string& value);

    std::string ToString() const;

    /**
     * @return the message associated with the status of this response, or the
     *  empty string if the status number is invalid
     */
    std::string GetStatusMessage() const;

    void SetContentLength();
};

/**
 * Handle server side includes.
 */
std::string PreprocessContent(const std::string& content, const std::string& path);

/**
 * @return the MIME type based on the extension of the given filename
 */
std::string GetMimeType(const std::string& filename);

/**
 * Used almost exclusively by Addressbook
 */
const char ETAG[] = "ETag";
const char IF_NONE_MATCH[] = "If-None-Match";
const char IF_MODIFIED_SINCE[] = "If-Modified-Since";
const char LAST_MODIFIED[] = "Last-Modified";
const char TRANSFER_ENCODING[] = "Transfer-Encoding";

/**
 * @return the decoded URI
 */
std::string DecodeURI(const std::string& data);

} // http
} // util
} // i2p

#endif // _HTTP_H__
