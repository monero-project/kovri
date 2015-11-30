#include "HTTP.h"
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <regex>
#include <fstream>
#include <boost/filesystem.hpp>
#include "Log.h"
#include "Reseed.h"
#include <boost/lexical_cast.hpp>

namespace i2p {
namespace util {
namespace http {

/**
 * @class Request
 * Used by HTTPServer
 */
void Request::parseRequestLine(const std::string& line)
{
    std::stringstream ss(line);
    ss >> method;
    ss >> uri;
}

void Request::parseHeaderLine(const std::string& line)
{
    const std::size_t pos = line.find_first_of(':');
    headers[boost::trim_copy(line.substr(0, pos))] = boost::trim_copy(line.substr(pos + 1));
}

void Request::parseHeader(std::stringstream& ss)
{
    std::string line;
    while(std::getline(ss, line) && !boost::trim_copy(line).empty())
        parseHeaderLine(line);

    has_header = boost::trim_copy(line).empty();
    if(!has_header)
        header_part = line;
    else
        header_part = "";
}

void Request::setIsComplete()
{
    auto it = headers.find("Content-Length");
    if(it == headers.end()) {
        // If Content-Length is not set, assume there is no more content 
        // TODO: Support chunked transfer, or explictly reject it
        is_complete = true;
        return;
    }
    const std::size_t length = std::stoi(it->second);
    is_complete = content.size() >= length;
}

Request::Request(const std::string& data)
{
    if(!data.empty())
        has_data = true;

    std::stringstream ss(data);

    std::string line;
    std::getline(ss, line);

    // Assume the request line is always passed in one go
    parseRequestLine(line);

    parseHeader(ss);

    if(has_header && ss) {
        const std::string current = ss.str();
        content = current.substr(ss.tellg());
    }

    if(has_header)
        setIsComplete();
}

std::string Request::getMethod() const
{
    return method;
}

std::string Request::getUri() const
{
    return uri;
}

std::string Request::getHost() const
{
    return host;
}

int Request::getPort() const
{
    return port;
}

std::string Request::getHeader(const std::string& name) const
{
    return headers.at(name);
}

std::string Request::getContent() const
{
    return content;
}

bool Request::hasData() const
{
    return has_data; 
}

bool Request::isComplete() const
{
    return is_complete;
}

void Request::clear()
{
    has_data = false;
    has_header = false;
    is_complete = false;
}

void Request::update(const std::string& data)
{
    std::stringstream ss(header_part + data);
    if(!has_header)
        parseHeader(ss);

    if(has_header && ss) {
        const std::string current = ss.str();
        content += current.substr(ss.tellg());
    }

    if(has_header)
        setIsComplete();
}

/**
 * @class Response
 * Used by HTTPServer
 */
Response::Response(int status, const std::string& content)
    : status(status), content(content), headers()
{

}

void Response::setHeader(const std::string& name, const std::string& value)
{
    headers[name] = value;
}

std::string Response::toString() const
{
    std::stringstream ss;
    ss << "HTTP/1.1 " << status << ' ' << getStatusMessage() << "\r\n";
    for(auto& pair : headers)
        ss << pair.first << ": " << pair.second << "\r\n";
    ss << "\r\n" << content; 
    return ss.str();
}

std::string Response::getStatusMessage() const
{
    switch(status) {
        case 105:
            return "Name Not Resolved";
        case 200:
            return "OK";
        case 400:
            return "Bad Request";
        case 404:
            return "Not Found";
        case 408:
            return "Request Timeout";
        case 500:
            return "Internal Server Error";
        case 502:
            return "Not Implemented";
        case 504:
            return "Gateway Timeout";
        default:
            return std::string();
    }
}

void Response::setContentLength()
{
    setHeader("Content-Length", std::to_string(content.size()));
}

std::string preprocessContent(const std::string& content, const std::string& path)
{
    const boost::filesystem::path directory(path); // Given path is assumed to be clean

    static const std::regex re(
        "<\\!\\-\\-\\s*#include\\s+virtual\\s*\\=\\s*\"([^\"]*)\"\\s*\\-\\->"
    );

    boost::system::error_code e;

    std::string result;

    std::smatch match;
    auto it = content.begin();
    while(std::regex_search(it, content.end(), match, re)) {
        const auto last = it;
        std::advance(it, match.position());
        result.append(last, it);
        std::advance(it, match.length());

        // Read the contents of the included file
        std::ifstream ifs(
            boost::filesystem::canonical(directory / std::string(match[1]), e).string(),
            std::ios_base::in | std::ios_base::binary
        );
        if(e || !ifs)
            continue;

        std::string data;
        ifs.seekg(0, ifs.end);
        data.resize(ifs.tellg());
        ifs.seekg(0, ifs.beg);
        ifs.read(&data[0], data.size());
        
        result += data; 
    }

    // Append all of the remaining content
    result.append(it, content.end());

    return result;
}

std::string getMimeType(const std::string& filename)
{
    const std::string ext = filename.substr(filename.find_last_of("."));
    if(ext == ".css")
        return "text/css";
    else if(ext == ".js")
        return "text/javascript";
    else if(ext == ".html" || ext == ".htm")
        return "text/html";
    else
        return "application/octet-stream";
}

/**
 * Used by Reseed
 */
std::string httpHeader (const std::string& path, const std::string& host, const std::string& version)
{
    std::string header =
	"GET " + path + " HTTP/" + version + "\r\n" +
	"Host: " + host + "\r\n" +
	"Accept: */*\r\n" +
	"User-Agent: Wget/1.11.4\r\n" +
	"Connection: close\r\n\r\n";
    return header;
}

std::string GetHttpContent (std::istream& response)
{
    std::string version, statusMessage;
    response >> version; // HTTP version
    int status;
    response >> status; // status
    std::getline (response, statusMessage);
    if(status == 200) // OK
    {
	bool isChunked = false;
        std::string header;
        while(!response.eof() && header != "\r")
	{
            std::getline(response, header);
            auto colon = header.find (':');
            if(colon != std::string::npos)
	    {
                std::string field = header.substr (0, colon);
               if(field == TRANSFER_ENCODING)
                   isChunked = (header.find("chunked", colon + 1) != std::string::npos);
            }
        }
        std::stringstream ss;
        if(isChunked)
            MergeChunkedResponse(response, ss);
        else
            ss << response.rdbuf();

        return ss.str();
    } else {
	LogPrint("HTTP response ", status);
	return "";
    }
}

void MergeChunkedResponse(std::istream& response, std::ostream& merged)
{
    while(!response.eof()) {
	std::string hexLen;
	int len;
	std::getline(response, hexLen);
	std::istringstream iss(hexLen);
	iss >> std::hex >> len;
	if(!len)
	    break;
        char* buf = new char[len];
        response.read(buf, len);
        merged.write(buf, len);
        delete[] buf;
        std::getline(response, hexLen); // read \r\n after chunk
    }
}

std::string httpsRequest (const std::string& address)
{
    url u(address);
    if (u.m_port == 80) u.m_port = 443;
	i2p::data::TlsSession session (u.m_host, u.m_port);

    if (session.IsEstablished ())
    {
	// send request
	std::stringstream ss;
	ss << httpHeader(u.m_path, u.m_host, "1.1");
	session.Send ((uint8_t *)ss.str ().c_str (), ss.str ().length ());

	// read response
	std::stringstream rs;
	while (session.Receive (rs))
	    ;
        return GetHttpContent (rs);
    } else
	return "";
}

url::url(const std::string& url)
{
    m_portstr = "80";
    m_port = 80;
    m_user = "";
    m_pass = "";

    parse(url);
}

void url::parse(const std::string& url)
{
   using namespace std;

    /**
    * This is a hack since colons are a part of the URI scheme
    * and slashes aren't always needed. See RFC 7595.
    * */
    const string prot_end("://");

    // Separate scheme from authority
    string::const_iterator prot_i = search(
	url.begin(), url.end(), prot_end.begin(), prot_end.end()
    );

    // Prepare for lowercase result and transform to lowercase
    m_protocol.reserve(distance(url.begin(), prot_i));
    transform(
	url.begin(), prot_i,
	back_inserter(m_protocol), ptr_fun<int, int>(tolower)
    );

    // TODO: better error checking and handling
    if(prot_i == url.end())
	return;

    // Move onto authority. We assume it's valid and don't bother checking.
    advance(prot_i, prot_end.length());
    string::const_iterator path_i = find(prot_i, url.end(), '/');

    // Prepare for lowercase result and transform to lowercase
    m_host.reserve(distance(prot_i, path_i));
    transform(
	prot_i, path_i,
	back_inserter(m_host), ptr_fun<int, int>(tolower)
    );

    // Parse user/password, assuming it's valid input
    auto user_pass_i = find(m_host.begin(), m_host.end(), '@');
    if(user_pass_i != m_host.end())
    {
        string user_pass = string(m_host.begin(), user_pass_i);
        auto pass_i = find(user_pass.begin(), user_pass.end(), ':');
	if (pass_i != user_pass.end())
	{
	    m_user = string(user_pass.begin(), pass_i);
            m_pass = string(pass_i + 1, user_pass.end());
        } else
            m_user = user_pass;

        m_host.assign(user_pass_i + 1, m_host.end());
    }

    // Parse port, assuming it's valid input
    auto port_i = find(m_host.begin(), m_host.end(), ':');
    if(port_i != m_host.end())
    {
	m_portstr = string(port_i + 1, m_host.end());
        m_host.assign(m_host.begin(), port_i);
        try {
            m_port = boost::lexical_cast<decltype(m_port)>(m_portstr);
        } catch(const exception& e) {
            m_port = 80;
        }
    }

    // Parse query, assuming it's valid input
    string::const_iterator query_i = find(path_i, url.end(), '?');
    m_path.assign(path_i, query_i);
    if(query_i != url.end())
        ++query_i;
    m_query.assign(query_i, url.end());
}

std::string urlDecode(const std::string& data)
{
    std::string res(data);
    for(size_t pos = res.find('%'); pos != std::string::npos; pos = res.find('%', pos + 1))
    {
	const char c = strtol(res.substr(pos + 1, 2).c_str(), NULL, 16);
	res.replace(pos, 3, 1, c);
    }
    return res;
}

} // http
} // util
} // i2p
