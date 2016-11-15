# So, you've installed Kovri. Now what?

## Step 1. Open your NAT/Firewall
1. Choose a port between ```9111``` and ```30777```
2. **Save this port to your configuration file** (`kovri.conf`)
3. Poke a hole in your NAT/Firewall to allow incoming TCP/UDP connections to that port (See notes below if you don't have access)

Notes:

- **Don't share your port number with anyone as it will effect your anonymity!**
- If you don't save the port, kovri will randomly generate a new one on each startup (you also have the choice to pass the port with the `--port` flag on each startup).
- If you do not have access to your NAT, see instructions in [BUILDING](https://github.com/monero-project/kovri/blob/master/doc/BUILDING.md) for your OS. 

## Step 2. Configure Kovri

For a full list of options:

```bash
$ ./kovri --help
```

For complete detailed options:

- `kovri.conf` configuration file for router and client
- `tunnels.conf` configuration file for client/server tunnels

## Step 3. Run Kovri
```bash
$ cd build/ && ./kovri
```

- Wait 5-10 minutes or so to get bootstrapped into the network before attempting to use services

## Step 4. Join us on IRC
1. Startup your [IRC client](https://en.wikipedia.org/wiki/List_of_IRC_clients)
2. Setup your client to connect to kovri's IRC port (default 6669). This will connect you to the Irc2P network (I2P's IRC network)
3. Join `#kovri` and `#kovri-dev`

## Step 5. Browse an I2P website (garlic-site/eepsite)
1. Startup a browser of your choosing (preferably a browser devoted to kovri usage)
2. Configure your browser by reading [these instructions](https://geti2p.net/en/about/browser-config) **but instead of port 4444 and 4445** change HTTP proxy port to **4446** and SSL proxy port *also* to **4446**
3. Visit http://check.kovri.i2p

Notes:

- **Just like with Tor, one doesn't need SSL to safely and securely use the network**
- SSL site support and outproxy service is not currently implemented
- If someone gives you a .i2p address that's not in your address book, use the `Jump` service at http://stats.i2p/i2p/lookup.html
- Look through hosts.txt in your data directory to view a list of default sites you can easily visit
- Overall, HTTP Proxy and address book implementation are in development and not yet feature-complete

## Step 6. Host your own garlic-service (garlic-site/eepsite)
- Read `tunnels.conf` to learn how to set a server tunnel to point to the service you are hosting

## Step 7. Enjoy!
- Read more about Kovri in the [Moneropedia](https://getmonero.org/knowledge-base/moneropedia/kovri).
- Open your feature requests or report bugs on our [issues tracker](https://github.com/monero-project/kovri/issues)
- Learn more about the I2P network on the [java I2P website](https://geti2p.net/en/docs)
