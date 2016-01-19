--
-- run i2p router with no clients on port 50050
--

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
i2lua.Wait()
print("Exiting...")
