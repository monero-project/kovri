#ifndef _HTTP_H__
#define _HTTP_H__

#include <string>
#include <map>
#include <sstream>

namespace i2p {
namespace util {
namespace http {

class Request {

    void parseRequestLine(const std::string& line);

    void parseHeaderLine(const std::string& line);

    void parseHeader(std::stringstream& ss);

    void setIsComplete();
public:
    Request() = default;

    Request(const std::string& data);

    std::string getMethod() const;

    std::string getUri() const;

    std::string getHost() const;

    int getPort() const;

    /**
     * @throw std::out_of_range if no such header exists
     */
    std::string getHeader(const std::string& name) const;

    std::string getContent() const;

    bool hasData() const;

    bool isComplete() const;

    void clear();

    void update(const std::string& data);

private:
    std::string header_part;

    std::string method;
    std::string uri;
    std::string host;
    std::string content;
    int port;
    std::map<std::string, std::string> headers;
    bool has_data;
    bool has_header;
    bool is_complete;
};

class Response {
public:
    Response() = default;

    Response(int status, const std::string& content = "");

    /**
     * @note overrides existing header values with the same name
     */
    void setHeader(const std::string& name, const std::string& value);

    std::string toString() const;

    /**
     * @return the message associated with the status of this response, or the
     *  empty string if the status number is invalid
     */
    std::string getStatusMessage() const;

    void setContentLength();

private:
    int status;
    std::string content;
    std::map<std::string, std::string> headers;
};

/**
 * Handle server side includes.
 */
std::string preprocessContent(const std::string& content, const std::string& path);

/**
 * @return the MIME type based on the extension of the given filename
 */
std::string getMimeType(const std::string& filename);

/**
 * Used almost exclusively by Addressbook
 */
const char ETAG[] = "ETag";
const char IF_NONE_MATCH[] = "If-None-Match";
const char IF_MODIFIED_SINCE[] = "If-Modified-Since";
const char LAST_MODIFIED[] = "Last-Modified";
const char TRANSFER_ENCODING[] = "Transfer-Encoding";

/**
 * Header for HTTPS requests.
 * @return a string of the complete header
 */
std::string httpHeader(const std::string& path, const std::string& host, const std::string& version);

/**
 * @return the content of the given HTTP stream without headers
 */
std::string GetHttpContent(std::istream& response);

/**
 * Merge chunks of a HTTP response into the gien std:ostream object.
 */
void MergeChunkedResponse(std::istream& response, std::ostream& merged);

/**
 * Perform an HTTPS request.
 * @return the result of the request, or an empty string if it fails
 */
std::string httpsRequest(const std::string& address);

/**
 * @return the decoded url
 */
std::string urlDecode(const std::string& data);

/**
 * @class url provides functionality for parsing URLs.
 */
class url {
    /**
     * The code for parse() was originally copied/pasted from
     * https://stackoverflow.com/questions/2616011/easy-way-to-parse-a-url-in-c-cross-platform
     *
     * This function is a URI parser (not a URL parser) and is hack at best.
     * See cpp-netlib for a better URI parsing implementation with Boost.
     *
     * Note: fragments are not parsed by this function (if they should
     * ever be needed in the future).
     *
     * @param string url
     */
    void parse(const std::string& url);
    public:
	/**
         * Parse a URI given as a string.
         */
	url(const std::string& url);
    public:
        std::string m_protocol, m_host, m_path, m_query, m_portstr;
        unsigned int m_port;
        std::string m_user, m_pass;
};

} // http
} // util
} // i2p

#endif // _HTTP_H__
