# Evaluate RTT for QUIC packets


### Team
Bhavana Shobhana, Shaleen Garg

### Introduction

Round Trip Time (RTT) metrics are central in making a lot of policy decisions like load balancing and exposing
traffic-interception attacks. 
Accurate RTT measurements typically require bidirectional TCP network trace but this might not be 
available in the real world. This \cite{workshop} paper approximates RTT for networks with single directional
TCP network trace. 
In this project, we would like to evaluate the accuracy of single directional RTT measurements 
on network traces.
Specifically we are going to do the following:
1. 
2. 
3. Evaluate RTT for QUIC packets

### QUIC HOW-TO

Below are the exact steps needed to run a simple QUIC server and client. We recommend a two node config from Cloudlab such as XXXX. Note, that quic installation will take upto 80 GB of storage, so choose an appropriate storage. We are assuming that it is an ubuntu machine. Other flavours might have different instructions.

#### Get Code

##### Install depot_tools
```
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$PATH:/path/to/depot_tools" ##can also add this to .bashrc
```
##### Get Chromium code
Note that since QUIC protocol is not in upstream linux kernel, only user-space implementations exist. We are going to use chromium implementation of QUIC for our tests.
```
/path/to/quic_rtt_eval/install-build-deps.sh ##Installs all dependencies for compiling
mkdir chromium && cd chromium
fetch chromium ##fetch is a command in depot_tools
```
Fetch command will take atleast 45 mins. It will populate all of chromium code which also contains QUIC example code.

##### Compile QUIC server/client
Once chromium is fetched, ```src``` has all the code.
In order to compile, we do the following:
```
cd src
gn gen out/Debug ##gn (depot_tools) generates a compilation folder out/Debug
autoninja -C out/Debug quic_server quic_client ##Compiles server and client ~5 mins
```

At the end of these ```out/Debug``` should contain two binaries ```quic_server``` and ```quic_client```.

##### Generate Certificates
QUIC requires certificates for communication between server and client. let us generate that

```
cd src/net/tools/quic/certs
./generate-certs.sh
```
This will generate the server's certificate and public key. This script also generates a CA certificate in```src/net/tools/quic/certs/out/2048-sha256-root.pem```. This has to be added to the OS's certificate store.
```
sudo apt install libnss3-tools
sudo certutil -d sql:$HOME/.pki/nssdb -N ##Creates a new DB
sudo certutil -d sql:$HOME/.pki/nssdb -A -t "C,C,C" -n quic_certificate -i net/tools/quic/certs/out/2048-sha256-root.pem ##adds new certificate
```

##### Run QUIC server/client
Now lets run the example.com website using quic_server.

To setup the website
```
mkdir ~/quic-data
cd ~/quic-data
wget -p --save-headers https://www.example.org
```
We need to edit index.html and adjust headers:
```
**Remove (if it exists):** "Transfer-Encoding: chunked"
**Remove (if it exists):** "Alternate-Protocol: ..."
**Add:** X-Original-Url: https://www.example.org/
```

Once these are done, spawn two terminals for server and client:

```
./src/out/Debug/quic_server \
 --quic_response_cache_dir=$HOME/quic-data/www.example.org \
 --certificate_file=src/net/tools/quic/certs/out/leaf_cert.pem \
 --key_file=src/net/tools/quic/certs/out/leaf_cert.pkcs8
```
```
./src/out/Debug/quic_client --host=127.0.0.1 --port=6121 https://www.example.org/
```
Client  will print out index.html. This is intended behaviour.
Note: to print verbose output from either server or client append ```--v=3``` to the commands

Alternatively, google-chrome can be used to as client.
```
#Installing Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
```
```
#Setting up Env Variables for SSL Key log file (For Decrypting Packets in Wireshark)
echo "export SSLKEYLOGFILE='$HOME/sslkeyfile.log'" >> ~/.bashrc
source ~/.bashrc
```

```
#Chrome as Client
google-chrome --headless --dump-dom --incognito --no-proxy-server --enable-quic \
--user-data-dir=/tmp/chrome-profile --origin-to-force-quic-on=www.example.org:443 \
--host-resolver-rules='MAP www.example.org:443 127.0.0.1:6121' https://www.example.org
```
This will print index.html.

