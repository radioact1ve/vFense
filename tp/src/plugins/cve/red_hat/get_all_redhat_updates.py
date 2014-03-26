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
        content=request.content
    return(content)

def make_html_folder(dname):
    PATH = HTML_DIR_REDHAT
    DIR = dname
    fpath = (PATH + DIR)
    if not os.path.exists(fpath):
        os.makedirs(fpath)
    return(fpath)
    
def write_content_to_file(file_path, file_name, content=None):
    dfile = (file_path + '/' + file_name)
    if not os.path.exists(dfile):
        msg_file = open(dfile, 'wb')
        content = content
	if content:
            msg_file.write(content)
            msg_file.close()
    return(dfile)

def get_rh_data(dfile):
    datafile=dfile
    if os.stat(datafile).st_size > 0:
        fo=open(datafile, 'r+')
        data=fo.read()
        data1=data.split('=')
        data2=[x for x in data1 if x]

        summary = None
        smry = re.search('1\.\s+Summary:\n\n(\w.*)\n\n.*2.', data, re.DOTALL)
        if smry:
            summary = smry.group(1)

        descriptions = None
        desc=(re.search('Description:\n\n(\w.*)\n\n.*\s+Solution', data, re.DOTALL))
        if desc:
            descriptions=desc.group(1)
	
        solutions = None
        sol = (re.search('Solution:\n\n(\w.*)\n\n.*\.\s+Bugs fixed', data, re.DOTALL))
        if sol:
            solutions=sol.group(1)
        #bug_fixed=re.search('5\.\s+Bugs fixed:\n\n(\w.*)\n\n.*6\.\s+Package List', data, re.DOTALL).group(1)
        
        pkg_list = None
        pkg = (re.search('Package List:\n\n(\w.*)\n\n.*\.\s+References', data, re.DOTALL))
        if pkg:
            pkg_list=pkg.group(1)
	
        references = None
        ref = (re.search('References:\n\n(\w.*)\n\n.*\.\s+Contact', data, re.DOTALL))        
        if ref:
            references=ref.group(1)

        vulnerability_id = None
        aid = (re.search(r'Advisory\sID:.*', data))
        if aid:
            vulnerability_id = (aid.group()).split(':')[1].strip()
        
        product = None
        prod=(re.search(r"Product:\s.*", data))
        if prod:
            product=prod.group().split(':')[1].strip()
        
        reference_url = None
        aurl=re.search(r"Advisory\sURL:\s.*", data)
        if aurl:
	        reference_url=aurl.group().split(':',1)[1].strip()
	    
        issue_date = None
        idate=(re.search(r"Issue\sdate:\s.*", data))
        if idate:
            issue_date=idate.group().split(':')[1].strip()
	    
        cve_ids = None
        cve_name=(re.search(r"CVE\sNames:\s+(\w.*)", data,))
        if cve_name:
            cves=cve_name.group().split(':')[1].strip()
            cve_ids=cves.split()

        
        parse_data={
            "Vulnerability_id":vulnerability_id,
            "Product":product,
            "issue_date": issue_date,
            "reference_url": reference_url,
            "cve_ids": cve_ids,
            "Summary": summary,
            "Descriptions": descriptions,
            "Solutions": solutions,
            "Packages" : pkg_list,
            "References": references,
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

def get_hlink_updates(thread):
    dlinks = []
    cve_updates = []
    req=requests.get(thread)
    if req.ok:
        url2 = thread
        date=url2.split('/')[-2]
        tsoup=BeautifulSoup(req.text)
        fpath=make_html_folder(dname=date)
        for mlink in tsoup.find_all('a'):
             if "msg" in mlink.get('href'):
                 hlink = (URL +date + '/' + mlink.get('href'))
                 fpath = fpath
                 print hlink
                 fname = (hlink.split('/')[-1])
                 pre_data=parse_hdata(hlink)
                 dfile = write_content_to_file(file_path=fpath, file_name=fname, content=pre_data)
                 cve_data = get_rh_data(dfile)
                 cve_updates.append(cve_data)
                 #dlinks.append(hlink)
        return(cve_updates) 

def get_all_data():
    path = HTML_DIR_REDHAT
    cve_infos = []
    threads=get_threads()
    if threads:
        cur_thread=threads.pop(0)
        cur_updates = get_hlink_updates(cur_thread)
        write_data = write_cve_updates(updates=str(cur_updates))
        cve_infos.append(cur_updates)

        pre_threads=threads
        for thread in threads:
            date = thread.split('/')[-2]
            dpath = (path + date)
            if not os.path.exists(dpath):
                pre_updates = get_hlink_updates(thread)
                write_cve_updates(updates=str(pre_updates))
                cve_infos.append(pre_updates)
    return(cve_infos)   

### this function is just to test the output. It will be replaced with db insertion soon.
def write_cve_updates(updates=None):
    if updates:
        cpath = (HTML_DIR_REDHAT + 'cve_updates.txt')
        cve_file =open(cpath, 'wb+')
        content = updates
        cve_file.write(content)
        cve_file.close()
    return(cve_file)

"""
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
"""


