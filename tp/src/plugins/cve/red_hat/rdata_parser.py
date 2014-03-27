import requests
from bs4 import BeautifulSoup

url1="https://www.redhat.com/archives/rhsa-announce/"
#url2="https://www.redhat.com/archives/rhsa-announce"
req=requests.get(url1)
soup=BeautifulSoup(req.text)

threads=[]
dlink=[]
for link in soup.find_all('a'):
    href=link.get('href')
    if "thread" in href:
	threads.append(url1+href)

for thread in threads:
    req=requests.get(thread)
    if req.status_code==200:
        url2=thread
        date=url2.split('/')[-2]
        req2=requests.get(url2)
        soup2=BeautifulSoup(req2.text)
        for mlink in soup2.find_all('a'):
            if "msg" in mlink.get('href'):
                dlink.append(url1+date+'/'+mlink.get('href'))

for link in dlink:
    print link
#url3=dlink[0]
#req3=requests.get(url3)
#soup3=BeautifulSoup(req3.text)
#print encode(soup3.text)
