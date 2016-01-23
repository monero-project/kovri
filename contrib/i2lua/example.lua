--
-- run i2p router with no clients on port 50050
--


local c = 5

while c > 0 do
  print("sleeping...")
  i2lua.Sleep(100)
  c = c - 1
end

function select_peers(dest)
   print("selecting peers for", dest.base32())
end
   


print("Starting i2lua")



-- initialize i2lua router to ise port 50050
port = 50050
print("Using port",port)
i2lua.Init(port)

-- start the router up
i2lua.Start()
print("Router Up")

-- wait for the router to stop
-- the program will wait here or until SIGINT or a crash
print("wait for exit...")
i2lua.Wait()
print("Exiting...")
