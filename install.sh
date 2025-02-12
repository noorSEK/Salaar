
#! /bin/bash 
sudo apt install -y net-tools
speedtest
sudo apt install lolcat -y
echo "Installing Requirements........" 
sudo apt update -y
sudo apt upgrade -y
sudo apt install python -y
sudo apt install python2 -y
sudo apt install python3 -y
sudo apt install python-pip -y
sudo apt install python3-pip -y
sudo apt install git -y
sudo apt install php -y
sudo apt install lolcat -y
sudo apt install figlet -y
sudo apt install -y curl 
sudo apt install -y wget 
sudo apt install -y unzip 
sudo apt install -y jq 
sudo apt install -y dnsutils 
sudo apt install -y whois 
sudo apt install -y nmap 
sudo apt install -y masscan 
sudo apt install -y tmux
sudo apt install -y npm
sudo apt install -y build-essential cmake make gcc 
sudo apt install python3.12-venv -y
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------Installing Go-Lang-------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+] Installing Go-Lang....." 
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
cp go1.23.4.linux-amd64.tar.gz /root/
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------Installing SubDomains Finders--------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+] Installing Assestfinder..." 
go install github.com/tomnomnom/assetfinder@latest
cp /root/go/bin/assetfinder /usr/local/bin
echo "[+] Installing SubFinder......." 
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
cp /root/go/bin/subfinder /usr/local/bin/
echo "[+] Installing Findomain........" 
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/findomain
findomain --help
echo "[+] Installing Amass......." 
go install -v github.com/owasp-amass/amass/v3/...@master
cp /root/go/bin/amass /usr/local/bin/
echo "[+] Installing SubList3r........." 
git clone https://github.com/aboul3la/sublist3r.git 
mv sublist3r /opt/
pip3 install -r /opt/sublist3r/requirements.txt
#---------------------------------------------------------------------------------------------------------------------
#------------------------------------------Installing Url Crawlers ---------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+] Installing Waybackurls....." 
go install github.com/tomnomnom/waybackurls@latest
cp /root/go/bin/waybackurls /usr/local/bin/
echo "[+] Installing Katana....." 
go install github.com/projectdiscovery/katana/cmd/katana@latest
cp /root/go/bin/katana /usr/local/bin/
echo "[+] Installing gau - Get All Urls" 
go install github.com/lc/gau/v2/cmd/gau@latest
cp /root/go/bin/gau /usr/local/bin/
echo "[+] Installing gauplus........" 
go install github.com/bp0lr/gauplus@latest
cp /root/go/bin/gauplus /usr/local/bin/
echo "[+] Installing Paramspider......" 
git clone https://github.com/devanshbatham/paramspider.git
mv paramspider /opt/
pip3 install -r /opt/paramspider/requirements.txt
#---------------------------------------------------------------------------------------------------------------------
#--------------------------------------Installing Subs Live Checker---------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "[+]Installing httpx........" 
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
cp /root/go/bin/httpx /usr/local/bin/
echo "[+]Installing httprobe......"
go install github.com/tomnomnom/httprobe@latest 
cp /root/go/bin/httprobe /usr/local/bin/
#---------------------------------------------------------------------------------------------------------------------
#------------------------------------------------Installing Sql Map---------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------
echo "Installing Sqlmap......" 
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap
mv sqlmap /opt/
#----------------
echo "Installing qsreplace....." 
go install github.com/tomnomnom/qsreplace@latest
cp /root/go/bin/qsreplace /usr/local/bin/
echo "[+] INstalling Fuzzing Templates...."
git clone https://github.com/projectdiscovery/fuzzing-templates.git
echo "[+]Installing Nuclei...."
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
cp /root/go/bin/nuclei /usr/local/bin
nuclei 
cp -r fuzzing-templates /root/
echo "[+]Installing Notify...."
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
cp /root/go/bin/notify /usr/local/bin
echo "[+]Installing Notify...."
rm -r /root/nuclei-templates/ssl/
rm /root/fuzzing-templates/crlf/cookie-injection.yaml
echo "[+]Installing urlfinder...."
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
cp /root/go/bin/urlfinder /usr/local/bin

echo "[+]Installing Chaos...."
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
cp /root/go/bin/chaos /usr/local/bin

echo "[+]Installing Hakrawler...."
go install github.com/hakluke/hakrawler@latest
cp /root/go/bin/hakrawler /usr/local/bin

echo "[+]Installing Mantra...."
go install github.com/Brosck/mantra@latest
cp /root/go/bin/mantra /usr/local/bin


go install github.com/Brosck/mantra@latest


echo "[+] Installing Go-Lang....." 
wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
cp go1.23.4.linux-amd64.tar.gz /root/
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version
