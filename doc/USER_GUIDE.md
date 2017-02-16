# So, you've installed Kovri. Now what?

## Step 1. Open your NAT/Firewall
1. Choose a port between ```9111``` and ```30777```
2. **Save this port to your configuration file** (`kovri.conf`)
3. Poke a hole in your NAT/Firewall to allow incoming TCP/UDP connections to that port (See notes below if you don't have access)

Notes:

- If you don't save the port, kovri will randomly generate a new one on each startup (you also have the choice to pass the port with the `--port` flag on each startup).
- If you do not have access to your NAT, see instructions in [BUILDING](https://github.com/monero-project/kovri/blob/master/doc/BUILDING.md) for your OS.
- **Don't share your port number with anyone as it will effect your anonymity!**

## Step 2. (Recommended) Operational security

- Consider creating a designated `kovri` user and run kovri only using that user
- If using Linux, consider using a hardened kernel (such as [grsec](https://en.wikibooks.org/wiki/Grsecurity) with RBAC)
- After installing the appropriate resources in your kovri data path, considering setting appropriate access control with [setfacl](https://linux.die.net/man/1/setfacl), [umask](https://en.wikipedia.org/wiki/Umask), or whatever your OS uses for ACL
- Never share your port number with anyone as it will effect your anonymity!

**Note: see kovri.conf to find your data path for Linux/OSX/Windows**

## Step 3. Configure Kovri, setup tunnels

For a full list of options:

```bash
$ ./kovri --help
```

For complete options with details:

- `kovri.conf` configuration file for router and client
- `tunnels.conf` configuration file for client/server tunnels

## Step 4. (Optional) Setup tunnels

In short, *client tunnels* are tunnels which you use to connect to other services and *server tunnels* are used for when you host service(s) (and other people connect to your service).

By default, you will have client tunnels setup for IRC (Irc2P) and email (i2pmail). To add/remove client tunnels, see `tunnels.conf`.

When creating server tunnel(s), you'll need to create *persistent private keys*. To do so, uncomment or create `keys = your-keys.dat` and replace `your-keys` with an appropriate name. **Do not share your private `.dat` file with anyone, and be sure to make a backup!**

Once setup, your [Base32 address](https://getmonero.org/knowledge-base/moneropedia/base32-address) will be shown in your log after you start kovri. You can also find the address in a text file along with the private keys file in your kovri data path in the `client/keys` directory. The address inside this `.txt` text file is safe to distribute so other people can connect to your service.

Example:

- Private keys file: `client/keys/your-keys.dat`
- Public [Base32](https://getmonero.org/knowledge-base/moneropedia/base32-address)/[Base64](https://getmonero.org/knowledge-base/moneropedia/base64-address) address: `client/keys/your-keys.dat.txt`

**Note: see kovri.conf to find your data path for Linux/OSX/Windows**

## Step 5. (Optional) Register your new [eepsite](https://getmonero.org/knowledge-base/moneropedia/eepsite)

**Stop! Until [#498](https://github.com/monero-project/kovri/issues/498) is resolved, consider only registering your service with Kovri and *not* stats.i2p!**

- Open a request with `[Subscription Request] your-host.i2p` (replace your-host.i2p with your desired hostname) on the [Kovri issue tracker](https://github.com/monero-project/kovri/issues)
- In the request body, paste the contents of your public `.txt` file that was mentioned in the previous step
- After review, we will add your host and sign the subscription
- Done!

## Step 6. Run Kovri
```bash
$ cd build/ && ./kovri
```
- Wait 5 minutes or so to get bootstrapped into the network before attempting to use services

## Step 7. Join us on IRC
1. Startup your [IRC client](https://en.wikipedia.org/wiki/List_of_IRC_clients)
2. Setup your client to connect to kovri's IRC port (default 6669). This will connect you to the Irc2P network (I2P's IRC network)
3. Join `#kovri` and `#kovri-dev`

## Step 8. Browse an I2P website (garlic-site/eepsite)
1. Startup a browser of your choosing (preferably a browser devoted to kovri usage)
2. Configure your browser by reading [these instructions](https://geti2p.net/en/about/browser-config) **but instead of port 4444 and 4445** change HTTP proxy port to **4446** and SSL proxy port *also* to **4446**
3. Visit http://check.kovri.i2p

Notes:

- **Just like with Tor, one doesn't need SSL to safely and securely use the network**
- SSL site support and outproxy service is not currently implemented
- If someone gives you a .i2p address that's not in your address book, use the `Jump` service at http://stats.i2p/i2p/lookup.html
- Look through hosts.txt in your data directory to view a list of default sites you can easily visit
- Overall, HTTP Proxy and address book implementation are in development and not yet feature-complete

## Step 9. Enjoy!
- Read more about Kovri in the [Moneropedia](https://getmonero.org/knowledge-base/moneropedia/kovri).
- Open your feature requests or report bugs on our [issues tracker](https://github.com/monero-project/kovri/issues)
- Learn more about the I2P network on the [java I2P website](https://geti2p.net/en/docs)

# Container Options

## Snapcraft

On Linux systems, use snapcraft for easy deployment.

### Step 1. Get the Kovri source repo

```bash
$ git clone --recursive https://github.com/monero-project/kovri
```

### Step 2. Install snapcraft

- Refer to your distribution's package manager for snapcraft and [snapd](https://snapcraft.io/docs/core/install)

On Ubuntu, simple run:
```bash
$ sudo apt-get install snapcraft
```

### Step 3. Create the snap

```bash
$ cd kovri/ && snapcraft && sudo snap install *.snap --dangerous
```
Note: the --dangerous flag is needed only because the snap has not been signed (you built it yourself though, so this shouldn't be an issue)

### Step 4. Run Kovri with snapcraft

```bash
$ snap run kovri
```

## Docker

### Step 1. Install Docker
Installing Docker is outside the scope of this document, please see the [docker documentation](https://docs.docker.com/engine/installation/)

### Step 2. Configuring / Open Firewall

The docker image comes with the defaults of kovri, but can be configured as explained in earlier sections.

You should choose a random port and open that port (see earlier sections).

### Step 3. Running

#### Default Settings
```bash
KOVRI_PORT=42085 && sudo docker run -p 127.0.0.1:4446:4446 -p 127.0.0.1:6669:6669 -p $KOVRI_PORT --env KOVRI_PORT=$KOVRI_PORT geti2p/kovri
```

#### Custom Settings
Where `./kovri-settings/` contains `kovri.conf` and `tunnels.conf`.
```bash
KOVRI_PORT=42085 && sudo docker run -p 127.0.0.1:4446:4446 -p 127.0.0.1:6669:6669 -p $KOVRI_PORT --env KOVRI_PORT=$KOVRI_PORT -v kovri-settings:/home/kovri/.kovri/config:ro geti2p/kovri
```
