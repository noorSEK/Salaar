#! /bin/bash 
url=$1

figlet "TheLionRecon" 
echo "                 @Abbas Cyber Security    " 

if [ ! -d "$url" ]; then
      mkdir $url
fi
if [ ! -d "$url/recon" ]; then
      mkdir $url/recon
fi

if [ ! -d "$url/params_vuln" ]; then
          mkdir $url/params_vuln
fi

if [ ! -d "$url/subs-vuln" ]; then
          mkdir $url/subs-vuln
fi

if [ ! -d "$url/subs-vuln/false_positive" ]; then
          mkdir $url/subs-vuln/false_positive
fi

if [ ! -d "$url/params_vuln/false_positive" ]; then
          mkdir $url/params_vuln/false_positive
fi

if [ ! -d "$url/recon/EyeWitness" ]; then
      mkdir $url/recon/EyeWitness
fi



#---------------------------------------------------------------------------------
#-----------------------------Finding SubDomains----------------------------------
#----------------------------------------------------------------------------------


echo "[+]Enumurating SubDomains Using Assetfinder..." 
assetfinder $url >> $url/recon/assetfinder.txt
cat $url/recon/assetfinder.txt | grep $url >> $url/recon/final.txt
rm $url/recon/assetfinder.txt

echo "[+]Enumurating SubDomains Using SubFinder..." 
subfinder -d $url -o $url/recon/subfinder.txt
cat $url/recon/subfinder.txt | grep $url >> $url/recon/final.txt
rm $url/recon/subfinder.txt

echo "[+]Enumurating SubDomains Using Findomain..." 
findomain -t $url -q >> $url/recon/findomain.txt
cat $url/recon/findomain.txt | grep $url >> $url/recon/final.txt
rm $url/recon/findomain.txt

echo "[+]Enumurating SubDomains Using Sublist3r..." 
python3 /opt/sublist3r/sublist3r.py -d $url -o $1/recon/sublist3r.txt
cat $url/recon/sublist3r.txt | grep $url >> $url/recon/final.txt
rm $1/recon/sublist3r.txt 

echo "[+]Enumurating SubDomains Using Amass..." 
amass enum -d $url >> $url/recon/amass.txt
cat $url/recon/amass.txt | grep $url >> $url/recon/final.txt
rm $url/recon/amass.txt

echo "[+]Filtering Repeated Domains........." 
cat $url/recon/final.txt | sort -u | tee $url/recon/final_subs.txt 
rm $url/recon/final.txt 

echo "[+]Total Unique SubDomains" 
cat $url/recon/final_subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Filtering Live SubDomains--------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Removing Dead Domains Using httpx....." 
cat $url/recon/final_subs.txt | httpx --silent >> $url/recon/live_check.txt

echo "[+]Removing Dead Domains Using httprobe....." 
cat $url/recon/final_subs.txt | httprobe >> $url/recon/live_check.txt

echo "[+]Analyzing Both httpx & httprobe....."
cat $url/recon/live_check.txt | sort -u | tee $url/recon/live_subs.txt 

echo "[+]Total Unique Live SubDomains....."
cat $url/recon/live_subs.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-----------------------------------Enumurating Parameters-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Enumurating Params From Paramspider...." 
python3 /opt/paramspider/paramspider.py --level high -d $url -p noor -o $1/recon/params.txt
echo "[+]Enumurating Params From Waybackurls...." 
cat $1/recon/live_subs.txt | waybackurls | grep = | qsreplace noor >> $url/recon/params.txt
echo "[+]Enumurating Params From katana...." 
katana -u $url/recon/live_subs.txt -d 200 | grep = | qsreplace noor >> $url/recon/params.txt
echo "[+]Enumurating Params From gau Tool...." | lolcat
gau --subs  $url | grep = | qsreplace noor >> $url/recon/params.txt 
echo "[+]Enumurating Params From gauPlus Tool...." 
cat $url/recon/live_subs.txt | gauplus | grep = | qsreplace noor >> $url/recon/params.txt
echo "[+]Enumurating Params From urlfinder Tool...." 
urlfinder -d $url/recon/live_subs.txt -all | grep = | qsreplace noor >> $url/recon/params.txt

echo "[+]Filtering Dups..." 
cat $url/recon/params.txt | sort -u | tee $url/recon/final_params.txt 

rm $url/recon/params.txt

echo "[+]Total Unique Params Found" 
cat $url/recon/final_params.txt | wc -l
#--------------------------------------------------------------------------------------------------
#-------------------------------Checking For HTMLi && RXSS-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Testing For HTML Injection...." 
cat $url/recon/final_params.txt | qsreplace '"><u>hyper</u>' | tee $url/recon/temp.txt && cat $url/recon/temp.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "><u>hyper</u>" && echo "$host"; done >> $url/htmli.txt
cat $url/htmli.txt | notify
#--------------------------------------------------------------------------------------------------
#-------------------------------Scanning With Nuclei-----------------------------------------
#--------------------------------------------------------------------------------------------------

cat $url/recon/live_subs.txt | nuclei -t /root/nuclei-templates/ -s critical -rl 3 -c 2 >> $1/nuclei.txt
cat $url/recon/live_subs.txt | nuclei -t /root/nuclei-templates/ -s high -rl 3 -c 2 >> $1/nuclei.txt
cat $url/recon/live_subs.txt | nuclei -t /root/nuclei-templates/ -s medium -rl 3 -c 2 >> $1/nuclei.txt
cat $url/recon/live_subs.txt | nuclei -t /root/nuclei-templates/ -s low -rl 3 -c 2 >> $1/nuclei.txt
cat $url/recon/live_subs.txt | nuclei -t /root/nuclei-templates/ -s unknown -rl 3 -c 2 >> $1/nuclei.txt
cat $1/nuclei.txt | notify
#--------------------------------------------------------------------------------------------------
#-------------------------------Scanning With Nuclei-----------------------------------------
#--------------------------------------------------------------------------------------------------
echo "[+]Fuzzing For Openredirects...." 
cat $url/recon/final_params.txt | qsreplace 'https://example.com/' | while read host do ; do curl -s -L $host  | grep "<title>Example Domain</title>" && echo "$host" ; done >> $1/open-redirects.txt
cat  $1/open-redirects.txt | notify
#--------------------------------------------------------------------------------------------------
#-------------------------------Fuzzing With Nuclei-----------------------------------------
#--------------------------------------------------------------------------------------------------
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/cmdi >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/crlf >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/csti >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/lfi >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/redirect >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/rfi >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/sqli >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/ssrf >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/xss >> $1/fuzz.txt
cat $url/recon/final_params.txt | nuclei -t /root/fuzzing-templates/xxe >> $1/fuzz.txt
cat $1/fuzz.txt | notify

echo "$url Fuzzing Done...." | notify
echo "$url Fuzzing Done...." | notify
echo "$url Fuzzing Done...." | notify
echo "$url Fuzzing Done...." | notify
echo "$url Fuzzing Done...." | notify
