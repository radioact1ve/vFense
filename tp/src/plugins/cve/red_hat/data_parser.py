import re
import requests
from bs4 import BeautifulSoup

uri='https://www.redhat.com/archives/rhsa-announce/2014-March/msg00029.html'
req=requests.get(uri)
soup=BeautifulSoup(req.text)
pre=soup.pre.text
data=(pre.strip()).encode('utf-8')
print data
#print re.search('1\.\s+Summary:\n\n(\w.*)\n\n.*2', data)
