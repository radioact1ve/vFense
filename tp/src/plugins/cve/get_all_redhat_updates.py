from bs4 import BeautifulSoup
import requests
import re
import sys
import logging
import logging.config
from time import mktime, sleep
from datetime import datetime
from vFense.db.client import r

from vFense.utils.common import month_to_num_month
from vFense.plugins.cve import *
from vFense.plugins.cve.cve_constants import *
from vFense.plugins.cve.cve_db import *
from vFense.plugins.cve.bulletin_parser import build_bulletin_id

#URL = "https://www.redhat.com/archives/rhsa-announce/"
URL = REDHAT_ARCHIVE

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

def get_rpm_pkgs(dfile):
    rpm_pkgs = []
    datafile=dfile
    if os.stat(datafile).st_size > 0:
        fo=open(datafile, 'r+')
        data=fo.read()
        pkg_list=re.search('6\.\s+Package List:\n\n(\w.*)\n\n.*7\.\s+References', data, re.DOTALL)
        if pkg_list:
            pkg_info = pkg_list.group(1)
            pkgs = pkg_info.split()
            for pkg in pkgs:
                if '.rpm' in pkg and not 'ftp://' in pkg:
                    rpm_pkgs.append(pkg) 
    return(rpm_pkgs)

def get_rh_cve_ids(dfile):
    cve_ids = []
    datafile=dfile
    if os.stat(datafile).st_size > 0:
        fo=open(datafile, 'r+')
        data=fo.read()
        cves=(re.search(r"CVE\sNames:\s+(\w.*)", data,re.DOTALL))
        if cves:
            cve_data = (cves.group()).split(':')[1].strip()
            for cve in cve_data.split():
                if 'CVE-' in cve:
                    cve_ids.append(cve)
    return(cve_ids)
            
def get_rh_data(dfile):
    datafile=dfile
    if os.stat(datafile).st_size > 0:
        fo=open(datafile, 'r+')
        data=fo.read()

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
        
        pkg_list = get_rpm_pkgs(dfile=dfile)
	
        references = None
        ref = (re.search('References:\n\n(\w.*)\n\n.*\.\s+Contact', data, re.DOTALL))        
        if ref:
            references=ref.group(1)

        vulnerability_id = None
        aid = (re.search(r'Advisory\sID:.*', data))
        if aid:
            vulnerability_id = (aid.group()).split(':', 1)[1].strip()
        
        product = None
        prod=(re.search(r"Product:\s.*", data))
        if prod:
            product=prod.group().split(':',1)[1].strip()
        
        reference_url = None
        aurl=re.search(r"Advisory\sURL:\s.*", data)
        if aurl:
	        reference_url=aurl.group().split(':',1)[1].strip()
	    
        issue_date = None
        idate=(re.search(r"Issue\sdate:\s.*", data))
        if idate:
            issue_date=idate.group().split(':',1)[1].strip()
            date_posted = datetime.strptime(issue_date, "%Y-%m-%d").strftime('%s')
	    
        cve_ids = get_rh_cve_ids(dfile=dfile)
        
        ID = build_bulletin_id(data = vulnerability_id)
        print ID
        parse_data={
            "id": '',
            "date_posted": date_posted,
            "bulletin_id":vulnerability_id,
            "bullentin_summary": summary,
            "bulletin_details": descriptions,
            "apps" : pkg_list,
            "cve_ids": cve_ids,
            "support_url": reference_url,
            "solutions": solutions,
            "references": references,
            "product":product,
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
                 if cve_data:
                    cve_updates.append(cve_data)
        insert=insert_into_bulletin_collection_for_redhat(bulletin_data=cve_updates)
        return(insert)

def update_all_redhat_data():
    path = HTML_DIR_REDHAT
    threads=get_threads()
    if threads:
        for thread in threads:
            date = thread.split('/')[-2]
            dpath = (path + date) 
            pre_updates = get_hlink_updates(thread)