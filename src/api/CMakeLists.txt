set(API_SRC
  "Datagram.cpp"
  "I2PControl/I2PControl.cpp"
  "I2PControl/I2PControlServer.cpp"
  "I2PTunnel/HTTPProxy.cpp"
  "I2PTunnel/I2PTunnel.cpp"
  "I2PTunnel/SOCKS.cpp"
  "Streaming.cpp"
)

include_directories("." "../" "../core/")

add_library(${API_NAME} ${API_SRC})
target_link_libraries(${API_NAME})
