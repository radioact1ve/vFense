from bs4 import BeautifulSoup
import requests
import re
import sys
import logging
import logging.config
from time import mktime
from datetime import datetime
from vFense.db.client import r

from vFense.utils.common import month_to_num_month
from vFense.plugins.cve import *
from vFense.plugins.cve.cve_constants import *

URL = "https://www.redhat.com/archives/rhsa-announce/"

logging.config.fileConfig('/opt/TopPatch/conf/logging.config')
logger = logging.getLogger('cve')

def parse_hdata(hlink):
    uri=hlink
    request=requests.get(uri)
    if request.ok:
        hdata=request.content
        pre_data=(re.search(r'<pre>.*</pre>?',hdata, re.DOTALL).group())

    return(pre_data)

def make_html_folder(dname):
    PATH = HTML_DIR_REDHAT
    DIR = dname
    fpath = (PATH + DIR)
    if not os.path.exists(fpath):
        os.makedirs(fpath)
    return(fpath)
    
def write_content_to_file(file_path, file_name, data):
    dfile = (file_path + '/' + file_name)
    msg_file = open(dfile, 'wb')
    content = None
    content = data
    msg_file.write(content)
    msg_file.close()
    return(dfile)

def get_rh_data(dfile):
    datafile=dfile
    fo=open(datafile, 'r+')
    data=fo.read()
    fo.close()
    data1=data.split('=')
    data2=[x for x in data1 if x]
    vulnerability_id=(re.search(r'Advisory\sID:.*', data).group()).split(':')[1].strip()
    product=(re.search(r"Product:\s.*", data).group()).split(':')[1].strip()
    reference_url=(re.search(r"Advisory\sURL:\s.*", data).group()).split(':',1)[1].strip()
    issue_date=(re.search(r"Issue\sdate:\s.*", data).group()).split(':')[1].strip()
    cves=(re.search(r"CVE\sNames:\s+(\w.*)", data,).group()).split(':')[1].strip()
    cve_ids=cves.split()
    summary=re.search('1\.\s+Summary:\n\n(\w.*)\n\n.*2\.\s+Relevant', data, re.DOTALL).group(1)
    descriptions=re.search('3\.\s+Description:\n\n(\w.*)\n\n.*4\.\s+Solution', data, re.DOTALL).group(1)
    solutions=re.search('4\.\s+Solution:\n\n(\w.*)\n\n.*5\.\s+Bugs fixed', data, re.DOTALL).group(1)
    #bug_fixed=re.search('5\.\s+Bugs fixed:\n\n(\w.*)\n\n.*6\.\s+Package List', data, re.DOTALL).group(1)
    pkg_list=re.search('6\.\s+Package List:\n\n(\w.*)\n\n.*7\.\s+References', data, re.DOTALL).group(1)
    references=re.search('7\.\s+References:\n\n(\w.*)\n\n.*8\.\s+Contact', data, re.DOTALL).group(1)
    parse_data={
        "Vulnerability_id":vulnerability_id,
        "Product":product,
        "issue_date": issue_date,
        "reference_url":reference_url,
        "cve_ids":cve_ids,
        "Summary": summary.replace('\n',''),
        "Descriptions": descriptions,
        "Solutions": solutions.replace('\n',''),
        "Packages" : pkg_list.replace('\n',''),
        "References": references.replace('\n',', '),
        }
    return(parse_data)
    
def get_threads():
    threads=[]
    req = requests.get(URL)
    soup= BeautifulSoup(req.text)
    for link in soup.find_all('a'):
        href=link.get('href')
        if "thread" in href:
            threads.append(URL+href)
    return(threads)

def get_hlink(thread):
    dlinks = []
    req=requests.get(thread)
    if req.ok:
        url2 = thread
        date=url2.split('/')[-2]
        req2=requests.get(url2)
        soup2=BeautifulSoup(req2.text)
        for mlink in soup2.find_all('a'):
             if "msg" in mlink.get('href'):
                   hlink = (URL +date + '/' + mlink.get('href'))
                   dlinks.append(hlink)
        return(dlinks) 

#def get_html_links():
#    dlink = []
#    threads= get_threads()
#    for thread in threads:
#        req=requests.get(thread)
#        if req.status_code==200:
#            url2=thread
#            date=url2.split('/')[-2]
#            req2=requests.get(url2)
#            soup2=BeautifulSoup(req2.text)
#            for mlink in soup2.find_all('a'):
#                if "msg" in mlink.get('href'):
#                    hlink=(URL+date+'/'+mlink.get('href'))
#                    hdata=parse_hdata(hlink=hlink)
#                    fpath = make_html_folder(dname = date)                    
#    return(dlink)
