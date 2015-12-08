#include "HTTP.h"

namespace i2p {
namespace util {
namespace http {

std::string HttpsDownload(const std::string& address)
{
    using namespace boost::asio;

    io_service service;
    boost::system::error_code ec;

    URI uri(address);

    // Ensures host is online
    auto query = ip::tcp::resolver::query(uri.m_Host, std::to_string(uri.m_Port));
    auto endpoint = ip::tcp::resolver(service).resolve(query, ec);

    if(!ec) {
        // Initialize SSL
        ssl::context ctx(service, ssl::context::sslv23); // TODO deprecated constructor
        ctx.set_options(ssl::context::no_tlsv1 | ssl::context::no_sslv3, ec);

	if(!ec) {
	    // Ensures that we only download from certified reseed servers
	    ctx.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
	    ctx.set_verify_callback(ssl::rfc2818_verification(uri.m_Host));
	    ctx.add_verify_path(i2p::util::filesystem::GetSSLCertsPath().string());

	    // Connect to host
            ssl::stream<ip::tcp::socket>socket(service, ctx);
            socket.lowest_layer().connect(*endpoint, ec);

            if(!ec) {
                // Initiate handshake
                socket.handshake(ssl::stream_base::client, ec);

                if(!ec) {
                    LogPrint(eLogInfo, "Connected to ", uri.m_Host, ":", uri.m_Port);

                    // Send header
                    std::stringstream sendStream;
                    sendStream << HttpHeader(uri.m_Path, uri.m_Host, "1.1");
                    socket.write_some(buffer(sendStream.str()));

                    // Read response / download
                    std::stringstream readStream;
                    char response[1024];
                    size_t length = 0;
                    do {
                        length = socket.read_some(buffer(response, 1024), ec);
                        if(length)
                            readStream.write(response, length);
		    }
                    while(!ec && length);
                        return GetHttpContent(readStream);

                 } else LogPrint(eLogError, "Could not initialize SSL context: ",
				                ec.message());

             } else LogPrint(eLogError, "SSL handshake failed: ",
			                    ec.message());

        } else LogPrint(eLogError, "Could not connect to ",
			uri.m_Host, ": ", ec.message());

    } else LogPrint(eLogError, "Could not resolve address ",
		    uri.m_Host, ": ", ec.message());
    return "";
}

URI::URI(const std::string& uri)
{
    m_PortString = "443";
    m_Port = 443;
    m_Path = "";
    m_Query = "";
    ParseURI(uri);
}

void URI::ParseURI(const std::string& uri)
{
   using namespace std;

    /**
    * This is a hack since colons are a part of the URI scheme
    * and slashes aren't always needed. See RFC 7595.
    * */
    const string prot_end("://");

    // Separate scheme from authority
    string::const_iterator prot_i = search(
	uri.begin(), uri.end(), prot_end.begin(), prot_end.end()
    );

    // Prepare for lowercase result and transform to lowercase
    m_Protocol.reserve(distance(uri.begin(), prot_i));
    transform(
	uri.begin(), prot_i,
	back_inserter(m_Protocol), ptr_fun<int, int>(tolower)
    );

    // TODO: better error checking and handling
    if(prot_i == uri.end())
	return;

    // Move onto authority. We assume it's valid and don't bother checking.
    advance(prot_i, prot_end.length());
    string::const_iterator path_i = find(prot_i, uri.end(), '/');

    // Prepare for lowercase result and transform to lowercase
    m_Host.reserve(distance(prot_i, path_i));
    transform(
	prot_i, path_i,
	back_inserter(m_Host), ptr_fun<int, int>(tolower)
    );

    // Parse port, assuming it's valid input
    auto port_i = find(m_Host.begin(), m_Host.end(), ':');
    if(port_i != m_Host.end())
    {
	m_PortString = string(port_i + 1, m_Host.end());
        m_Host.assign(m_Host.begin(), port_i);
        try {
            m_Port = boost::lexical_cast<decltype(m_Port)>(m_PortString);
        } catch(const exception& e) {
            m_Port = 443;
        }
    }

    // Parse query, assuming it's valid input
    string::const_iterator query_i = find(path_i, uri.end(), '?');
    m_Path.assign(path_i, query_i);
    if(query_i != uri.end())
        ++query_i;
    m_Query.assign(query_i, uri.end());
}

std::string HttpHeader(const std::string& path, const std::string& host,
                        const std::string& version)
{
    std::string header =
	"GET " + path + " HTTP/" + version + "\r\n" +
	"Host: " + host + "\r\n" +
	"Accept: */*\r\n" +
	"User-Agent: Wget/1.11.4\r\n" +
	"Connection: close\r\n\r\n";
    return header;
}

std::string GetHttpContent(std::istream& response)
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

/**
 * Used by HTTPProxy
 */
std::string DecodeURI(const std::string& data)
{
    std::string res(data);
    for(size_t pos = res.find('%'); pos != std::string::npos; pos = res.find('%', pos + 1))
    {
	const char c = strtol(res.substr(pos + 1, 2).c_str(), NULL, 16);
	res.replace(pos, 3, 1, c);
    }
    return res;
}

/**
 * @class Request
 * Used by HTTPServer
 */
void Request::ParseRequestLine(const std::string& line)
{
    std::stringstream ss(line);
    ss >> m_Method;
    ss >> m_URI;
}

void Request::ParseHeaderLine(const std::string& line)
{
    const std::size_t pos = line.find_first_of(':');
    m_Headers[boost::trim_copy(line.substr(0, pos))] = boost::trim_copy(line.substr(pos + 1));
}

void Request::ParseHeader(std::stringstream& ss)
{
    std::string line;
    while(std::getline(ss, line) && !boost::trim_copy(line).empty())
        ParseHeaderLine(line);

    m_HasHeader = boost::trim_copy(line).empty();
    if(!m_HasHeader)
        m_HeaderSection = line;
    else
        m_HeaderSection = "";
}

void Request::SetIsComplete()
{
    auto it = m_Headers.find("Content-Length");
    if(it == m_Headers.end()) {
        // If Content-Length is not set, assume there is no more content 
        // TODO: Support chunked transfer, or explictly reject it
        m_IsComplete = true;
        return;
    }
    const std::size_t length = std::stoi(it->second);
    m_IsComplete = m_Content.size() >= length;
}

Request::Request(const std::string& data)
{
    if(!data.empty())
        m_HasData = true;

    std::stringstream ss(data);

    std::string line;
    std::getline(ss, line);

    // Assume the request line is always passed in one go
    ParseRequestLine(line);

    ParseHeader(ss);

    if(m_HasHeader && ss) {
        const std::string current = ss.str();
        m_Content = current.substr(ss.tellg());
    }

    if(m_HasHeader)
        SetIsComplete();
}

std::string Request::GetMethod() const { return m_Method; }
std::string Request::GetUri() const { return m_URI; }
std::string Request::GetHost() const { return m_Host; }
int Request::GetPort() const { return m_Port; }
std::string Request::GetHeader(const std::string& name) const { return m_Headers.at(name); }
std::string Request::GetContent() const { return m_Content; }
bool Request::HasData() const { return m_HasData; }
bool Request::IsComplete() const { return m_IsComplete; }

void Request::Clear()
{
    m_HasData = false;
    m_HasHeader = false;
    m_IsComplete = false;
}

void Request::Update(const std::string& data)
{
    std::stringstream ss(m_HeaderSection + data);
    if(!m_HasHeader)
        ParseHeader(ss);

    if(m_HasHeader && ss) {
        const std::string current = ss.str();
        m_Content += current.substr(ss.tellg());
    }

    if(m_HasHeader)
        SetIsComplete();
}

/**
 * @class Response
 * Used by HTTPServer
 */
Response::Response(int status, const std::string& content)
    : status(status), content(content), headers() {}

void Response::SetHeader(const std::string& name, const std::string& value)
{
    headers[name] = value;
}

std::string Response::ToString() const
{
    std::stringstream ss;
    ss << "HTTP/1.1 " << status << ' ' << GetStatusMessage() << "\r\n";
    for(auto& pair : headers)
        ss << pair.first << ": " << pair.second << "\r\n";
    ss << "\r\n" << content; 
    return ss.str();
}

std::string Response::GetStatusMessage() const
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

void Response::SetContentLength()
{
    SetHeader("Content-Length", std::to_string(content.size()));
}

std::string PreprocessContent(const std::string& content, const std::string& path)
{
    const boost::filesystem::path directory(path); // Given path is assumed to be clean

    static const std::regex re(
        "<\\!\\-\\-\\s*#include\\s+virtual\\s*\\=\\s*\"([^\"]*)\"\\s*\\-\\->"
    );

    boost::system::error_code ec;

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
            boost::filesystem::canonical(directory / std::string(match[1]), ec).string(),
            std::ios_base::in | std::ios_base::binary
        );
        if(ec || !ifs)
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

std::string GetMimeType(const std::string& filename)
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

} // http
} // util
} // i2p
