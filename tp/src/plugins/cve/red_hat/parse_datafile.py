import re
import os
import simplejson as json
import json 

fo=open('data4.txt', 'r+')
data=fo.read()
fo.close()
data1=data.split('=')
data2=[x for x in data1 if x]
#print data2
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
print json.dumps(parse_data, sort_keys=True, 
    indent=4, separators=(',', ': '))
#print pkg_list
