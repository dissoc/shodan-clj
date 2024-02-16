;;; Copyright © 2024 Justin Bishop <mail@dissoc.me>

(ns shodan-clj.protocols
  (:require [camel-snake-kebab.core :as csk]))

(def protocols
  {:dicom              "Checks whether the DICOM service is running.",
   :voldemort          "Pings the Voldemort database.",
   :mumble-server
   "Grabs the version information for the Murmur service (Mumble server)",
   :unitronics-pcom
   "Collects device information for Unitronics PLCs via PCOM protocol.",
   :vault              "Determine wether vault is running & collect relevant info",
   :apple-airport-admin
   "Check whether the device is an Apple AirPort administrative interface.",
   :poison-ivy-rat     "Checks whether the device is running Poison Ivy.",
   :omron-tcp          "Gets information about the Omron PLC.",
   :proconos
   "Gets information about the PLC via the ProConOs protocol.",
   :andromouse
   "Checks whether the device is running the remote mouse AndroMouse service.",
   :bacnet             "Gets various information from a BACnet device.",
   :ldap-tcp           "LDAP banner grabbing module",
   :pptp               "Connect via PPTP",
   :iec-61850          "MMS protocol",
   :weblogic-t-3
   "Check whether the device operates the Oracle Weblogic T3 protocol",
   :fox                "Grabs a banner for proprietary FOX protocol by Tridium",
   :coap-dtls
   "Check whether the server supports the CoAP protocol with DTLS",
   :newline-tcp        "Connect to a server with TCP and send a newline.",
   :rdate              "Get the time from a remote rdate server",
   :dht                "Gets a list of peers from a DHT node.",
   :beanstalk          "Get general information about the Beanstalk daemon",
   :iota-rpc           "Grabs version information about the IOTA node.",
   :dnp-3              "A dump of data from a DNP3 outstation",
   :redis              "Redis banner grabbing module",
   :ms-sql             "Check whether the MS-SQL database server is running",
   :tuya               "Check whether a device supports the Tuya API",
   :postgresql
   "Collects system information from the PostgreSQL daemon",
   :line-printer-daemon
   "Get a list of jobs in the print queue to verify the device is a printer.",
   :portmap-udp
   "Get a list of processes that are running and their ports.",
   :ldap-udp           "CLDAP banner grabbing module",
   :dahua-dvr          "Grab the serial number from a Dahua DVR device.",
   :open-tcp           "Checks whether a port is open and nothing else.",
   :tibia              "Grab general information from Open Tibia servers",
   :ethernetip
   "Grab information from a device supporting EtherNet/IP over TCP",
   :clamav             "Determine whether a server is running ClamAV",
   :ethereum-rpc       "Grabs version information about the Ethereum node.",
   :ike-nat-t
   "Checks wheter a device is running a VPN using IKE and NAT traversal.",
   :echo-udp           "Checks whether the device is running echo.",
   :mikrotik-routeros
   "Check whether the device operates the Oracle Weblogic T3 protocol",
   :toshiba-pos        "Grabs device information for the IBM/ Toshiba 4690.",
   :xiaongmai-backdoor "Detect backdoor in xiaongmai devices.",
   :smtps              "Grab a banner and certificate for SMTPS servers",
   :flux-led           "Grab the current state from a Flux LED light bulb.",
   :matrikon-opc       "Checks whether the device is running Matrikon OPC.",
   :microhard          "Checks whether the device is running Microhard.",
   :zookeeper          "Grab statistical information from a Zookeeper node",
   :https-simple-new
   "HTTPS banner grabber only (no robots, sitemap etc.)",
   :pop-3-ssl          "Grab the secure POP3 welcome message",
   :dictionary
   "Connects to a dictionary server using the DICT protocol.",
   :crestron
   "Checks for other servers with the same serial number on the local network. AAAAAA is a dummy value.",
   :steam-ihs          "Steam In-Home Streaming protocol",
   :java-rmi           "Check whether the device is running Java RMI.",
   :nodata-tcp-small
   "Connect to a server without sending any data and store whatever it returns.",
   :coap               "Check whether the server supports the CoAP protocol",
   :upnp               "Collects device information via UPnP.",
   :smb
   "Grab a list of shares exposed through the Server Message Block service",
   :smarter-coffee
   "Checks the device status of smart coffee machines.",
   :http-supermicro
   "HTTP banner grabbing module for Supermicro servers",
   :tor-versions
   "Checks whether the device is running the Tor OR protocol.",
   :ubiquiti-discover
   "Grabs information about the Ubiquiti-powered device",
   :git                "Check whether git is running.",
   :netmobility        "Checks whether the device is a NetMobility.",
   :kafka              "Get information about a Kafka cluster.",
   :ibm-nje
   "Check whether the z/OS Network Job Entry service is running.",
   :bitcoin
   "Grabs information about a Bitcoin daemon, including any devices connected to it.",
   :portmap-tcp
   "Get a list of processes that are running and their ports.",
   :identd             "Check whether the service is running identd",
   :opc-ua             "Grab a list of nodes from an OPC UA service",
   :njrat              "Determine whether a server is running a njRAT C&C",
   :tor-control
   "Checks whether a device is running the Tor control service.",
   :newline-udp        "Connect to a server with UDP and send a newline.",
   :melsec-q-udp
   "Get the CPU information from a Mitsubishi Electric Q Series PLC.",
   :blackshades
   "Determine whether a server is running a Blackshades C&C",
   :memcache-udp
   "Get general information about the Memcache daemon responding on UDP",
   :nntp               "Get the welcome message of a Network News server",
   :consul
   "Determine wether consul is running & collect relevant info",
   :kerberos
   "Checks whether a device is running the Kerberos authentication daemon.",
   :imap-ssl           "Get the welcome message of the secure IMAP server",
   :realport           "Get the banner for the Digi Realport device",
   :dhcp
   "Send a DHCP INFORM request to learn about the lease information from the DHCP server.",
   :pcworx             "Gets information about PC Worx device.",
   :pop-3              "Grab the POP3 welcome message",
   :tacacs             "Check whether the device supports TACACS+ AAA.",
   :couchdb            "HTTP banner grabbing module",
   :gearman            "Gather usage information from a Gearman queue",
   :ssh                "Get the SSH banner, its host key and fingerprint",
   :hart-ip-udp        "Checks whether the IP is a HART-IP gateway.",
   :hbase              "Grab the status page for HBase database software.",
   :nodata-tcp
   "Connect to a server without sending any data and store whatever it returns.",
   :ftp                "Grab the FTP banner",
   :iscsi              "Determine whether a server is an iSCSI target",
   :moxa-nport
   "Attempts to grab information from Moxna Nport devices.",
   :nanocore-rat
   "Checks whether the device is a C2 for NanoCore RAT.",
   :lifx               "Check whether there is a BitTorrnt tracker running.",
   :modbus
   "Grab the Modbus device information via functions 17 and 43.",
   :general-electric-srtp
   "Check whether the GE SRTP service is active on the device.",
   :dns-udp
   "Try to determine the version of a DNS server by grabbing version.bind",
   :mongodb            "Collects system information from the MongoDB daemon.",
   :steam-a-2s
   "Get a list of IPs that NTP server recently saw and try to get version info.",
   :bgp                "Checks whether the device is running BGP.",
   :nodata-dtls
   "Check whether the service supports DTLS and store whatever is returned",
   :ard
   "Query the Apple Remote Desktop service for information about the device",
   :ibm-db-2-das
   "Grab basic information about the IBM DB2 Database Server.",
   :telnets            "Telnet wrapped in SSL banner grabbing module",
   :yahoo-smarttv
   "Checks whether the device is running the Yahoo Smart TV device communication service.",
   :citrix-apps
   "This module attempts to query Citrix Metaframe ICA server to obtain a published list of applications.",
   :tc-b
   "Cursory check whether a device is running the TC-B protocol",
   :cassandra
   "Get cluster information for the Cassandra database software.",
   :monero-rpc         "Collect information about the Monero daemon.",
   :snmp               "Performs an SNMP walk of the system OID",
   :orcus-rat          "Checks whether the device is a C2 for Gh0st RAT.",
   :wdbrpc
   "Checks whehter the WDB agent (used for debugging) is enabled on a VxWorks device.",
   :mqtt               "Grab a list of recent messages from an MQTT broker.",
   :natpmp             "Checks whether NAT-PMP is exposed on the device.",
   :amqp               "Grab information from an AMQP service",
   :x-11               "Connect to X11 w/ no auth and grab the resulting banner.",
   :gtp-v-1            "Checks whether the device is running a GPRS Tunnel.",
   :scpi               "Check for the SCPI protocol used by lab equipment",
   :rsync              "Get a list of shares from the rsync daemon.",
   :language-server-protocol
   "Checks whether the port is running a language server.",
   :serialnumbered
   "Checks for other servers with the same serial number on the local network. AAAAAA is a dummy value.",
   :remcos-pro-rat
   "Checks whether the device is a C2 for RemCos Pro 2.05",
   :libreoffice-impress
   "Check whether the LibreOffice Impress Remote Server is enabled",
   :openvpn
   "Checks whether the other server runs an OpenVPN that doesnt require TLS auth",
   :minecraft
   "Gets the server status information from a Minecraft server",
   :xmpp               "Sends a hello request to the XMPP daemon",
   :etcd               "Etcd cluster information",
   :secure-fox
   "Grabs a banner for proprietary FOX protocol by Tridium",
   :nodata-tcp-ssl
   "Connect to a server using SSL and without sending any data.",
   :lantronix-udp
   "Attempts to grab the setup object from a Lantronix device.",
   :ripple-rtxp        "Grabs the list of peers from an RTXP Ripple daemon.",
   :ibm-db-2-drda      "Checks for support of the IBM DB2 DRDA protocol.",
   :nanocore-122-rat
   "Checks whether the device is a C2 for NanoCore Version 1.2.2.0 Cracked",
   :hddtemp            "View hard disk information from hddtemp service.",
   :cisco-smi
   "Check whether the device supports the Cisco Smart Install feature.",
   :plc-5              "Checks whether the device is running Poison Ivy.",
   :vertx-edge
   "Checks whether the device is running the VertX/ Edge door controller.",
   :hifly              "Checks whether the HiFly lighting control is running.",
   :sap-router         "Check whether the SAP Router is active",
   :idevice            "Connects to an iDevice and grabs the property list.",
   :knx                "Grabs the description from a KNX service.",
   :ipmi
   "Checks whether a device is running IPMI remote management software.",
   :statsd-admin       "Gathers statistics from the StatsD service.",
   :qrat               "Determine whether a server is running a QRAT C&C",
   :ms-sql-monitor     "Pings an MS-SQL Monitor server",
   :teamviewer         "Determine whether a server is running TeamViewer",
   :steam-dedicated-server-rcon
   "Checks whether an IP is running as a Steam dedicated game server with remote authentication enabled.",
   :checkpoint-hostname
   "Get hostnames for the CheckPoint firewall and management station.",
   :nuclear-rat        "Checks whether the device is a C2 for Nuclear RAT.",
   :http               "HTTP banner grabbing module",
   :epmd
   "Get a list of Erlang services and the ports they are listening on",
   :smtp               "Get basic SMTP server response",
   :codesys            "Grab a banner for Codesys daemons",
   :telnet             "Telnet banner grabbing module",
   :rdp                "RDP banner grabbing module",
   :gardasoft-vision
   "Grabs the version for the Gardasoft controller.",
   :redlion-crimson-3
   "A fingerprint for the Red Lion HMI devices running CrimsonV3",
   :rip
   "Checks whether the device is running the Routing Information Protocol.",
   :onvif              "Check whether the Onvif camera is operating.",
   :kilerrat           "Determine whether a server is running a KilerRAT C&C",
   :dns-tcp
   "Try to determine the version of a DNS server by grabbing version.bind",
   :automated-tank-gauge
   "Get the tank inventory for a gasoline station.",
   :insteon-plm        "Checks whether the device is Insteon PLM type",
   :kamstrup           "Kamstrup Smart Meters",
   :sip                "Gets the options that the SIP device supports.",
   :printer-job-language
   "Get the current output from the status display on a printer",
   :whois              "Check whether the port is running WHOIS",
   :darktrack-rat
   "Checks whether the device is a C2 for DarkTrack RAT.",
   :ethernetip-udp
   "Grab information from a device supporting EtherNet/IP over UDP",
   :ghost-rat          "Checks whether the device is a C2 for Gh0st RAT.",
   :idera              "Grab target system info through Idera uptime agent system",
   :teradici-pcoip
   "Check whether the device is running Teradici PCoIP Management Console.",
   :oracle-tns         "Check whether the Oracle TNS Listener is running.",
   :s-7
   "Communicate using the S7 protocol and grab the device identifications.",
   :bittorrent-tracker
   "Check whether there is a BitTorrent tracker running.",
   :ajp                "Check whether the Tomcat server running AJP protocol",
   :ms-portmap-tcp
   "Queries an MSRPC endpoint mapper for a list of mapped services and gathered information.",
   :teradici-pcoip-old
   "Check whether the device is running Teradici PCoIP Management Console.",
   :http-simple-new
   "HTTP banner grabber only (no robots, sitemap etc.)",
   :rtsp-tcp           "Determine which options the RTSP server allows.",
   :pcanywhere-status
   "Asks the PC Anywhere status daemon for basic information.",
   :ike                "Checks wheter a device is running a VPN using IKE.",
   :auto
   "Detect the type of service that runs on the port and send the appropriate request.",
   :afp                "AFP server information grabbing module",
   :ventrilo
   "Gets the detailed status information from a Ventrilo server.",
   :netbios            "Grab NetBIOS information including the MAC address.",
   :quic               "Checks whether a service supports the QUIC HTTP protocol",
   :munin              "Check whether a Munin node is active and list its plugins",
   :mdns               "Perform a DNS-based service discovery over multicast DNS",
   :melsec-q-tcp
   "Get the CPU information from a Mitsubishi Electric Q Series PLC.",
   :mysql              "Grabs the version of the running MySQL server",
   :ikettle            "Check whether the device is a coffee machine/ kettle.",
   :udpxy              "Udpxy banner grabbing module",
   :ntp
   "Get a list of IPs that NTP server recently saw and try to get version info.",
   :wemo-http          "Connect to a Wemo Link and grab the setup.xml file",
   :imap               "Get the welcome message of the IMAP server",
   :https              "HTTPS banner grabbing module",
   :ldaps              "LDAPS banner grabbing module",
   :hbase-old
   "Grab the status page for old, deprecated HBase database software.",
   :riak               "Sends a ServerInfo request to Riak",
   :iec-104            "Banner grabber for the IEC-104 protocol.",
   :memcache           "Get general information about the Memcache daemon"})

(def all-protocols (->> protocols
                        (map (fn [[k v]]
                               (-> k
                                   csk/->snake_case
                                   name)))
                        set))
