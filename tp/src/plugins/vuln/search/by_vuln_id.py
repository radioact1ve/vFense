import re
import logging
import logging.config

<<<<<<< HEAD:tp/src/plugins/vuln/search/by_vuln_id.py
from vFense.errorz.error_messages import GenericResults
from vFense.plugins.vuln.cve import *
from vFense.plugins.vuln.cve._constants import *
import vFense.plugins.vuln.ubuntu.usn as usn
import vFense.plugins.vuln.windows.ms as ms
=======
from vFense.db.client import db_create_close, r, db_connect
from vFense.errorz.error_messages import GenericResults, PackageResults
from vFense.plugins.cve import *
from vFense.plugins.cve.cve_constants import *
from vFense.plugins.cve.search._db import get_ubu_vulnerability_data_by_vuln_id, \
    get_win_vulnerability_data_by_vuln_id, get_redhat_vulnerability_data_by_vuln_id
>>>>>>> f7247095462ffe3a5e2e7d8a26e6d6f1b3ca1487:tp/src/plugins/cve/search/by_vuln_id.py

logging.config.fileConfig('/opt/TopPatch/conf/logging.config')
logger = logging.getLogger('cve')

class RetrieveByVulnerabilityId(object):
    def __init__(
        self, username, customer_name, vuln_id,
        uri=None, method=None, count=30, offset=0
        ):

        self.vuln_id = vuln_id
        self.username = username
        self.customer_name = customer_name
        self.uri = uri
        self.method = method
        self.count = count
        self.offset = offset
        self.__os_director()

    def __os_director(self):
        if re.search('^MS', self.vuln_id, re.IGNORECASE):
            self.get_vuln_by_id = ms.get_vuln_data

        elif re.search('^USN-', self.vuln_id, re.IGNORECASE):
            self.get_vuln_by_id = usn.get_vuln_data

        elif re.search('^RHSA-', self.vuln_id):
            self.Collection = RedHatSecurityBulletinCollection
            self.Keys = RedhatSecurityBulletinKey
            self.get_vuln_by_id = get_redhat_vulnerability_data_by_vuln_id

    

    def get_vuln(self):
        data = self.get_vuln_by_id(self.vuln_id)
        if data:
            status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).information_retrieved(data, 1)
            )

        else:
            status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).invalid_id(self.vuln_id, 'vulnerability id')
            )

        return(status)
