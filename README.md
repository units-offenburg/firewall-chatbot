# firewall-bot
A simple chatbot designed to configure your firewall using ufw *Uncomplicated Firewall* which configures the systems iptables/nftables.

## step-by-step guide to run your first bot
We will use [deltabot](https://github.com/deltachat-bot/deltabot) as a chatbot framework.
The chat betweent client and chatbot is e2e encrypted with [autocrypt](https://autocrypt.org/).
To use the bot you will need an email address for the bot and a [Deltachat client](https://get.delta.chat/).

Caveat 1:
If the email address you plan on using for your bot belongs to a domain that does not host a mail server under that domain (e.g. botname@yourdomain but imap/smtp.yourhostersdomain), you need to make sure that the deltabot init routine can find a suitable autoconfig file.
Additionally this file has to be served using TLS encryption since the init routine will not use plain http to access the file.
You can use the supplied config-v1.1.xml file and adapt it to suit the domain your email address belongs to and serve it at https://yourdomain/mail/config-v1.1.xml
The init routine will then pick up the needed information automatically and set itself up for that account.
Of course there are different ways to accomplish this (autoconfig/autodiscover/.well-known etc.) but deltabot init will try pretty much every possible way to setup the given email address.

Caveat 2:
For using ufw, you have be root while installing and the bot (started manually or as a service) has to run as root.

INSTALLATION:
There are (at least) 3 ways to your own firewall-bot:
1. You use the python installation that is included in your OS (must be at least version 3.8) and install all packages listed in the Pipfile onto that. This approach is not recommended.
2. You create a virtual environment (using venv, which is included in python version 3.8+ or any other means of creating virtual python environments) and install the required packages into that virtual environment.
3. You follow this guide, which will make use of pipenv (and with it pyenv) to not only install the required python version (independent from your system python installation) into an environment solely used for the firewall-bot, but also install every required package.

In any case, please take a look at the last steps of the installation - even using pipenv you will have to manually install deltachat and subsequently deltabot.

The following step-by-step guide has been tested on a fresh installation of Ubuntu 20.04.2 LTS (generic kernel), it *should* also apply to lower versions and/or other debian-based distributions (but not guaranteed...).

- Make sure you are actually logged in as root (using sudo or sudo su will probably result in problems with PATH).
```
sudo su -
```
- Take care of installing all prerequisits for using pipenv:
assuming your installation is up to date, if not consider doing:
```
apt-get update && apt-get upgrade
```
- To install pipenv via the installer script you will need an existing python installation as well as the corresponding python distutils. Ubuntu 20.04.02 ships with Python 3.8.5 which will need the python3-distutils:
```
apt install python3-distutils
```
- Install git and packages needed for pyenv to build python:
```
apt install git build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev
```
- Install pyenv:
```
curl https://pyenv.run | bash
```
- Open the following file:
```
vi /root/.profile
```
- And insert these lines at the beginning:
```
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init --path)"
```
- Restart the logon session and check if pyenv is available in your PATH:
```
exit
sudo su -
pyenv --version
```
- To install pipenv, make sure to change the last part of the following command to reference your python installation (e.g. python instead of python3 in case you might have aliased python3):
```
curl https://raw.githubusercontent.com/pypa/pipenv/master/get-pipenv.py | python3
```
- To check if pipenv was installed successfully, run:
```
pipenv --version
```
Now all prerequisits are met and we can continue to install the firewall-bot.
If you are not installing on a fresh system and maybe already have iptables rules in place, it may be a good idea to save those rules:
```
iptables-save > /root/iptables-backup
iptables-legacy-save > /root/iptables-backup-legacy
```
You can later reapply them with:
```
iptables-restore /root/iptables-backup
iptables-restore /root/iptables-backup-legacy
```
- Create a directory where you'd like to have the firewall-bot project, in this guide we will use /fwbot in the "home" directory of root (/root):
```
mkdir /root/fwbot
```
- Move into your project directory, clone the firewall-bot repository and move into the repository directory:
```
cd /root/fwbot
git clone https://github.com/janekc/firewall-bot
cd /root/fwbot/firewall-bot
```
- Use pipenv to install the firewall-bot and its required packages and version of python:
```
pipenv install
```
(Answer 'Y' if you're asked to install CPython with Pyenv).
- Activate your newly created python environment:
```
pipenv shell
```
- Move into your project directory, clone the ufw master repository, move into the repository directory and use pip to install ufw (you might be able to get by using a version of ufw that is already installed on your system or available via apt - we recommend using the most recent master):
```
cd /root/fwbot
git clone -b master https://git.launchpad.net/ufw
cd /root/fwbot/ufw
pip install .
```
- Move back into your project directory:
```
cd /root/fwbot
```
- Use pip to install deltachat from devpi:
```
pip install --pre -i https://m.devpi.net/dc/master deltachat
```
- Use pip to install deltabot:
```
pip install deltabot
```
- Move into your firewall-bot repository directory:
```
cd /root/fwbot/firewall-bot
```
Now let's initialize the bot with an email address
```
deltabot init <email address> <password>
```
The bot should be ready to use by now, let's see if it works!
```
deltabot serve
```
If it does, you can add the firewall module
```
deltabot add-module firewall-bot.py
deltabot serve
```
Post-Installation (as root/sudo):
Make sure that no matter how restrictive your firewall-settings may be, the firewall-bot will always be able to fetch emails:
Insert the following lines into /etc/ufw/before.rules
```
# FWBOT
-A ufw-before-output -p tcp --dport 993 -j ACCEPT
-A ufw-before-output -p tcp --dport 465 -j ACCEPT
-A ufw-before-output -p udp --dport 53 -j ACCEPT
```
Additionally, if you want to make sure you always have SSH access, add this line ($PORT being the port you have set in your sshd config)
```
# SSHACCESS
-A ufw-before-input -p tcp --dport $PORT -j ACCEPT
```
Have the firewall-bot run as a system service:
- Move into your firewall-bot directory and activate the projects python environment:
```
cd *yourprojectdirectory*/firewall-bot
pipenv shell
```
- Display the path to the deltabot installation:
```
which deltabot
```
The output should look sth like this: /root/.local/share/virtualenvs/firewall-bot-DJhpAnUw/bin/deltabot.
You will need this full path to put in your service file. Exit the python environment to continue.
- Create a service file:
```
vi /etc/systemd/system/fwbot.service
```
- Insert the following into the service file:
```
[Unit]
Description=DeltaChatFirewallBot

[Service]
Type=simple
ExecStart=*your-path-to-deltabot* serve
Environment=PYTHONUNBUFFERED=1
SyslogIdentifier=fwbot

[Install]
WantedBy=multi-user.target
```
- After every change to service files do:
```
systemctl daemon-reload
```
Now you can use systemctl start/stop/status/enable/disable/restart/... fwbot.service like any other service.
At this point all "output" (stdout, stderr, print-statements) will be redirected by systemctl to syslog (/var/log/syslog).
You may want to change this behaviour:
- Open the syslog config
```
vi /etc/rsyslog.d/50-default.conf
```
- Insert the following into the config:
```
:programname,isequal,"fwbot"  /var/log/fwbot.log
```
- Restart the rsyslog daemon:
```
systemctl restart rsyslog
```
For the cherry on top, setup logrotation for fwbot-logging:
- Create a logrotate file:
```
vi /etc/logrotate.d/fwbot
```
- Insert the following into the logrotate file (daily zipping and max 5 logs - feel free to adapt this to your liking):
```
/var/log/fwbot.log {
    su root syslog
    daily
    rotate 5
    compress
    delaycompress
    missingok
    postrotate
        systemctl restart rsyslog > /dev/null
    endscript
}
```
- Run the rotation dry to make sure there are no errors:
```
logrotate -d /etc/logrotate.d/fwbot
```
- Run the rotation once:
```
logrotate --force /etc/logrotate.d/fwbot
```
