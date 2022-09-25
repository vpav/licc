from distutils.command.build_scripts import first_line_re
from genericpath import isfile
from inspect import currentframe
import os
import gzip
import logging
import posixpath
from tabnanny import check
from tkinter.tix import Tree
from typing import List
from xmlrpc.client import Boolean
import colorama
import pathlib
import nvdlib
import configparser
import re
#from nvdlib.classes import CVE
import xlsxwriter
import colorama
import sys

#
# Tool Settings
#
KERNEL_SRC_DIR = ""
TMP_DIR = ""
KERNEL_SRC_BASE_URL = "https://mirrors.edge.kernel.org/pub/linux/kernel/v{major}.x/linux-{major}.{minor}.{build}.tar.gz"
NIST_NVD_API_KEY = ""
CONSOLE_COLOR = False

#
# Kernel Settings
#
KERNEL_VERSION="4.14.290"
KERNEL_ARCH="aarch64"
KERNEL_CONFIG_FILE=""




class SourceChecker():
    MF_OK = 0
    MF_OFILE_NOT_FOUND = 1
    MF_UNCONDITIONAL = 2
    MF_INVALID_ENTRY_FOUND = 3
    MF_UNSUPPORTED_FILE_FORMAT = 4
    

    def __init__(self, kversion:str = ""):
        self.kernel_version = ""
        self.remote_url = ""
        self.root_path = ""    
        subdir = "linux-" + kversion
        self.root_path = os.path.join(KERNEL_SRC_DIR, subdir)
        logging.info("Source Checker initialized for Kernel " + kversion)

    def __download_src():
        pass

    def __extract_src():
        pass

    def __is_cached(self,version:str) -> bool:
        """Checks if Kernel Source for given kernel is already available"""
        # TODO: additional plausibility check
        cached = os.path.exists( self.root_path )
        if cached:
            logging.info("Kernel Source is cached")
        else:
            logging.info("Kernel Source is NOT cached")
        return cached
        

    def setup(self):
        """Sets up Source Checker, i.e. makes sure the proper kernel source is available"""
        # check if exists
        if not self.__is_cached(self.kernel_version):
            # download
            # extract
            # cleanup tmp (targz)
            pass
        pass

    def compile_switch_for_path(self, filepath:str) -> tuple[str, bool]:
        """
        Searches for a file in kernel source and returns the config parameter
        Returns empty string if nothing found
        """
        compileflag = ""
        uncertain_result = False

        # TODO / BUG: Propagate warnings about unsupported file types to give high-level indication about uncertainity in cve check result

        # normalize path to os specific
        filepath = filepath.replace(posixpath.sep, os.sep)
    
        # check if file exists in source
        fullpath = os.path.join( self.root_path, filepath )
        dirpath = os.path.dirname(fullpath)

        logging.debug("Searching for " + fullpath )

        if os.path.isfile(fullpath):
            logging.debug("Found " + filepath )
            filename = os.path.basename(fullpath)
            if filename.endswith('.c'):
                # check if c-file
                logging.debug("Is a C-File " )
        
                # check if makefile exists in same folder
                makefilepath = os.path.join(dirpath, 'Makefile')
                if os.path.isfile(makefilepath):
                    logging.debug("Found first-level makefile: " + makefilepath)

                    # parse makefile & search for reference
                    code, flag = self.__parse_makefile(makefilepath, filename, False)
                    
                    if code == self.MF_OFILE_NOT_FOUND:
                        compileflag = ""

                    elif code == self.MF_INVALID_ENTRY_FOUND:
                        # TODO: return uncertainity flag if invalid entry found
                        compileflag = ""
                    # TODO: if found without dependency: check parent folder for makefile (all levels, recursive)
                    elif code == self.MF_UNCONDITIONAL:
                        upperpath = os.path.dirname(dirpath)
                        foldername = os.path.basename(dirpath)
                        makefilepath_up = os.path.join(upperpath, 'Makefile')
                        if os.path.isfile(makefilepath_up):
                            logging.debug("Found second-level makefile: " + makefilepath_up)
                            code, flag = self.__parse_makefile(makefilepath_up, foldername, True)
                            if code == self.MF_OFILE_NOT_FOUND:
                                compileflag = ""
                            elif code == self.MF_INVALID_ENTRY_FOUND :
                                # TODO: return uncertainity flag if invalid entry found
                                compileflag = ""
                            elif code == self.MF_UNCONDITIONAL:
                                # TODO: add recursive check to iterate over all parent folders
                                # TODO: add uncertainitiy flag as long as recursive check is not available
                                uncertain_result = True
                                compileflag = ""
                            elif code == self.MF_UNSUPPORTED_FILE_FORMAT:
                                uncertain_result = True
                                compileflag = flag
                            else:
                                compileflag = flag
                            
                    elif code == self.MF_OK or code == self.MF_UNSUPPORTED_FILE_FORMAT:
                        # if found with dependency: return dependency
                        compileflag = flag
                        
        return compileflag, uncertain_result


    def __makefile_collapse_multline(self, makefilepath:os.PathLike) -> list[str]:
        """Open makefilepath, collapse makefile multilines, return list of single lines"""
        with open(makefilepath, 'r') as mfile:
            #
            # Preparation: Collapse multi-line comments
            #
            last_multi = False
            this_multi = False
            currentmultiline = ""
            outlines: List[str] = []

            for line in mfile.readlines():
                this_multi = line.endswith("\\\n")
                if last_multi == False and this_multi == True:
                    # multiline block start
                    currentmultiline = line.rstrip("\\\n")
                    
                elif last_multi == True and this_multi == True:
                    # multiline block append
                    currentmultiline += line.rstrip("\\\n")
                    
                elif last_multi == True and this_multi == False:
                    # multiline block end
                    currentmultiline += line.rstrip("\\\n")
                    outlines.append(currentmultiline)
                    
                else:
                    # no multiline block (add directly)
                    outlines.append(line.rstrip("\n"))
                    
                # shift vars
                last_multi = this_multi

            return outlines

    def __parse_makefile(self, makefilepath:os.PathLike, cfile:str, search_for_path:bool = False) -> tuple[int, str]:
        """Checks first-level makefile for c-file"""
        retcode = self.MF_OK
        retflag = ""
        found = False
        file_ok = True # Flag to control if an yet unsupported flag (e.g. ifeq) is in file

        # TODO: Add handling for multiple matches, i.e. if the file is referenced by multiple flags

        if search_for_path:
            cfile += "/" # add trailing slash to differentiate paths from other mentioning of foldername (e.g. ext4 vs ext4/ )
            ofilename = cfile
        else:
            ofilename = cfile[:-2] + '.o'
        
        outlines = self.__makefile_collapse_multline(makefilepath)

        #for line in mfile.readlines():
        for line in outlines:
            # TODO: adapt check for filename to match exactly. "in" does also incorrectly match file.c to alongerfile.c


            if re.search( r'\b' + ofilename + r'\b', line ) or line.endswith(ofilename):
                logging.debug("Found reference in Makefile")
                found = True

                # TODO / BUG: add handling for ifeq:
                # e.g.
                # CVE-2018-12896
                # ifeq ($(CONFIG_POSIX_TIMERS),y)
                # obj-y += posix-timers.o posix-cpu-timers.o posix-clock.o itimer.o
                # else
                # obj-y += posix-stubs.o
                # endif

                if "+=" in line:
                    firstpart = line.split("+=")[0].strip()
                else:
                    # try if := is the correct operator, but we need to do a split anyhow - in that case we don't get usable data
                    firstpart = line.split(":=")[0].strip()

                logging.debug(firstpart)

                if not firstpart.startswith('obj-'):
                    #logging.debug("Found makefile-line does not contain usable data")
                    pass
                #if firstpart == 'obj-y':
                if '-y' in firstpart or '-objs' in firstpart:
                    # object is unconditionally added
                    logging.debug("Found unconditional add in makefile")
                    retcode = self.MF_UNCONDITIONAL
                    
                elif '-$(' in firstpart:
                    # object is conditionally added
                    compileflag = firstpart.split('-$(')[1].split(')')[0]
                    logging.info( "Found matching flag: " + compileflag)
                    retcode = self.MF_OK
                    retflag = compileflag

                else:
                    # TODO: Add handling for those (rare) cases where a trailing slash is contained even though a folder is not references
                    # eg. # Now bring in any enabled 8250/16450/16550 type drivers.
                    # For the moment, just output a warning and declare the file unclean to add the uncertainity-flag
                    logging.warning( "Warning: Unknown line format: " + firstpart)
                    file_ok = False
                    

            elif "ifeq" in line:
                # workaround for currently unsupported ifeq
                # TODO: remove
                file_ok = False

        if found == False and file_ok:
            logging.info("Failed to find C-File in makefile")
            retcode = self.MF_OFILE_NOT_FOUND
        elif file_ok == False:
            logging.warning("Makefile contains unsupported feature, result may be invalid!")
            retcode = self.MF_UNSUPPORTED_FILE_FORMAT

        return retcode, retflag

    def __parse_makefile_path(self, makefilepath:os.PathLike, cfolder:str) -> tuple[int, str]:
        """Checks upper-level makefile for folder add"""
        retcode = self.MF_OK
        retflag = ""
        found = False
        file_ok = True

        cfolder += "/" # add trailing slash to differentiate paths from other mentioning of foldername (e.g. ext4 vs ext4/ )

        outlines = self.__makefile_collapse_multline(makefilepath)

        for line in outlines:
            # TODO: adapt check for folder name to match exactly. "in" does also incorrectly match file.c to alongerfile.c
            if cfolder in line:
                logging.debug("Found reference in Makefile")
                found = True
                
                # TODO: add handling for multi-lines:
                # e.g. 
                # obj-$(CONFIG_TTY)		+= tty_io.o n_tty.o tty_ioctl.o tty_ldisc.o \
                #  tty_buffer.o tty_port.o tty_mutex.o \
                #  tty_ldsem.o tty_baudrate.o tty_jobctrl.o \
                #  n_null.o

                firstpart = line.split("+=")[0].strip()
                logging.debug(firstpart)
                if not firstpart.startswith('obj-'):
                    logging.error("Found makefile-line does not contain usable data")
                #if firstpart == 'obj-y':
                if '-y' in firstpart:
                    # object is unconditionally added
                    logging.debug("Found unconditional add in makefile")
                    retcode = self.MF_UNCONDITIONAL
                    pass
                elif firstpart.startswith('obj-$('):
                    # object is conditionally added
                    compileflag = firstpart.split('obj-$(')[1].split(')')[0]
                    logging.info( "Found matching flag: " + compileflag)
                    retcode = self.MF_OK
                    retflag = compileflag
                    pass
            elif "ifeq" in line:
                # workaround for currently unsupported ifeq
                # TODO: remove
                file_ok = False

        if found == False and file_ok:
            logging.info("Failed to find C-File in makefile")
            retcode = self.MF_OFILE_NOT_FOUND
        elif file_ok == False:
            logging.warning("Makefile contains unsupported feature, result may be invalid!")
            retcode = self.MF_UNSUPPORTED_FILE_FORMAT

        return retcode, retflag


class ConfigChecker():
    CC_NOT_SET = 0
    CC_SET = 1
    CC_SET_MODULE = 2
    CC_SET_CUSTOM = 3
    CC_NOT_FOUND = 4

    def __init__(self, config_file:str):
        self.config_path = config_file
        self.cleanlines = []
        self.config = {}
        self.__load()
    
    def __load(self):
        self.cleanlines = []

        logging.info("Loading Kernel Config: " + self.config_path)

        with open(self.config_path, 'r') as cfile:

            lines = cfile.readlines() 

            # remove trailing crlf
            lines = [line.rstrip() for line in lines]
            # normalize not set
            lines = [line.replace("# CONFIG", "CONFIG") for line in lines ]

            # remove comments and empty lines
            for line in lines:
                if not line.startswith('#'):
                    if not line.strip() == "":
                        self.cleanlines.append(line)

            for line in self.cleanlines:
                if "=" in line:
                    a = line.split("=")
                    flag = a[0]
                    setting = a[1]
                    self.config[flag] = setting
                elif "is not set" in line:
                    a = line.split("is not set")
                    flag = a[0].strip()
                    setting = "NOTSET"
                    self.config[flag] = setting
                else:
                    logging.error("Kernel Config Parse Error at line: " + line)
                
    def check(self, flag:str):
        """Checks if flag is present in kernel config"""
        if flag in self.config:
            logging.debug("Found Flag in Config: " + flag)
            flagval = self.config[flag]
            if flagval == "y":
                return self.CC_SET, ""
            elif flagval == "m":
                return self.CC_SET_MODULE, ""
            else:
                return self.CC_SET_CUSTOM, flagval
        else:
            return self.CC_NOT_FOUND, ""

    def dump(self, output_path:str):
        """Writes the cleaned kernel config to file"""
        with open(output_path, 'w+') as ofile:
            for line in self.cleanlines:
                ofile.write(f"{line}\n")
        logging.debug("Dumped cleaned kernel config to " + output_path)


class CVE:
    description = ""
    CVSSv2 = 0.0
    CVSSv3 = 0.0
    CVSSv3severity = ""
    CVSSv3vector = ""
    impact = {}
    id = ""
    config = {}
    assigner = ""
    problemtype = {}
    references = {}
    publishDate = ""
    lastmodifiedDate = ""
    cwe = ""
    url = ""

    def __init__(self, dcve:nvdlib.classes.CVE):
        self.description = ""
        self.CVSSv2 = 0.0
        self.CVSSv3 = 0.0
        self.CVSSv3severity = ""
        self.CVSSv3vector = ""
        self.impact = {}
        self.id = ""
        self.config = {}
        self.assigner = ""
        self.problemtype = {}
        self.references = {}
        self.publishDate = ""
        self.lastmodifiedDate = ""
        self.cwe = ""

        self.id = dcve.id
        self.configs = dcve.configurations
        self.publishDate = dcve.publishedDate
        self.lastmodifiedDate = dcve.lastModifiedDate 

        try:
            self.CVSSv3 = dcve.v3score
        except AttributeError:
            # old CVEs have only v2 scores
            self.CVSSv2 = dcve.v2score

        self.description = dcve.cve.description.description_data[0].value
        self.configs = dcve.configurations
        self.cwe = dcve.cwe
        self.problemtype = dcve.cve.problemtype
        self.url = dcve.url

        try:
            self.CVSSv3vector = dcve.v3vector
        except AttributeError:
            pass

        self.references = dcve.cve.references
        
        pass


class ResultItem():

    def __init__(self, cve: CVE, result: int, flag:str, path:str, isUncertain:bool, reason:int) -> None:
        self.cve: CVE = cve
        self.result: int = result
        self.flag: str = flag
        self.path = path
        self.isUncertain: bool = isUncertain
        self.reason: int = reason
   
class ResultReason():
    R_NO_REASON = -1
    R_SF_NOT_FOUND = 0
    R_FLAG_SET = 1
    R_FLAG_NOT_SET = 2
    R_FLAG_NOT_FOUND = 3
    text: list[str] = [
        'The referenced source file was not found in kernel sources',
        'The controlling compile flag is set in the kernel config',
        'The controlling compile flag is not set in the kernel config',
        'The controlling compile flag is not found in the kernel config'
    ]

    def getText(self, reason:int) -> str:
        if reason == self.R_NO_REASON:
            return ""
        else:
            return self.text[reason]

class CVEManager():
    CHECK_CVE_APPLICABLE = 0
    CHECK_CVE_NOT_APPLICABLE = 1
    CHECK_INCONCLUSIVE = 2

    def __init__(self):
        self.kernel_version = ""
        self.remote_url = ""
        self.cpes = []
        self.cves: list[CVE] = []
        self.sc = SourceChecker(KERNEL_VERSION)
        self.cc = ConfigChecker(KERNEL_CONFIG_FILE)

        self.sc.setup()
        self.results:list[ResultItem] = []
    
    def check_cve(self, cve:CVE) -> tuple[int, str, str, bool, str]:
        """Checks if given CVE is applicable"""

        # TODO: check architecture
        # check kernel build config
        flag = ""
        sourcepath = ""

        sourcepath = self.extractpath(cve.description)
        if len(sourcepath) == 0:
            # inconlusive
            return self.CHECK_INCONCLUSIVE, flag, sourcepath, False, ResultReason.R_NO_REASON
        else:
            flag, uncertainity = self.sc.compile_switch_for_path(sourcepath)
            checkres, flagval = self.cc.check(flag)
            
            # check if file exists in source
            # normalize path to os specific
            checkpath = sourcepath.replace(posixpath.sep, os.sep)
            fullpath = os.path.join( self.sc.root_path, checkpath )
            if not os.path.isfile(fullpath):
                # File not found in sources -> not applicable
                logging.info("Reason: File not found in Source")
                return self.CHECK_CVE_NOT_APPLICABLE, flag, sourcepath, uncertainity, ResultReason.R_SF_NOT_FOUND

            if (checkres == self.cc.CC_SET or checkres == self.cc.CC_SET_CUSTOM or checkres == self.cc.CC_SET_MODULE):
                return self.CHECK_CVE_APPLICABLE, flag, sourcepath, uncertainity, ResultReason.R_FLAG_SET
            elif checkres == self.cc.CC_NOT_SET:
                return self.CHECK_CVE_NOT_APPLICABLE, flag, sourcepath, uncertainity, ResultReason.R_FLAG_NOT_SET
            elif checkres == self.cc.CC_NOT_FOUND:
                return self.CHECK_CVE_NOT_APPLICABLE, flag, sourcepath, uncertainity, ResultReason.R_FLAG_NOT_FOUND

    def check_cves(self):
        """Iterates over all CVEs found by update_cves() and checks for applicability"""
        for c in self.cves:
            logging.info("Processing " + c.id)
            
            a, flg, path, uncertainity, reason = self.check_cve(c)
            if a == self.CHECK_CVE_APPLICABLE:
                if CONSOLE_COLOR:
                    logging.info(colorama.Fore.LIGHTRED_EX + "[!]   APPLICABLE  " + colorama.Style.RESET_ALL )
                else:
                    logging.info( "[!]   APPLICABLE  " )
                
            elif a == self.CHECK_CVE_NOT_APPLICABLE:
                if CONSOLE_COLOR:
                    logging.info(colorama.Fore.LIGHTGREEN_EX + "[-]   NOT APPLICABLE  " + colorama.Style.RESET_ALL)
                else:
                    logging.info("[-]   NOT APPLICABLE  ")
                
            else:
                if CONSOLE_COLOR:
                    logging.info(colorama.Fore.LIGHTYELLOW_EX + "[?]   INCONCLUSIVE  " + colorama.Style.RESET_ALL)
                else:
                    logging.info("[?]   INCONCLUSIVE  ")

            logging.debug("-------------------------------------------")    
            ritem = ResultItem(c,a,flg,path, uncertainity, reason)
            self.results.append(ritem)

   
    def collectCPE(self, iter):
        #if type(iter) is dict:
            if "children" in iter:
                
                if iter.children:
                    # Children contains elements
                    a = []
                    for child in iter.children:
                        self.collectCPE(child)
                    
                else:
                    # Children contains NO elements
                    #print("CPE: ", iter.cpe_match)
                    self.cpes.append(iter.cpe_match)
                    
        #else:
        #    print("not a dict, but a ", type(iter))

    def update_cves(self):
        """Update local CVEs DB from NIST DB"""

        # user does NOT have api key
        # limit = 10 req / 60s

        # user has api key
        #
        # limit = 100 req / 60s
        r = nvdlib.searchCVE(cpeName = 'cpe:2.3:o:linux:linux_kernel:' + KERNEL_VERSION + ':*:*:*:*:*:*:*', key=NIST_NVD_API_KEY)
        cvelist = []
        truecvelist: list[CVE] = []
        falsepositivelist = []
        for cve in r:
            self.cpes = []
            falsepositive = True
            print("-----------------------------------------------")
            print(cve.id, end='')
            cvelist.append(cve.id)
            #print(cve.configurations)
            config = cve.configurations.nodes
            #print(config)
            
            for eachNode in config:
                ### Part 1: Elements with Children
                if "children" in eachNode:
                    #print("Has Children!")
                    self.collectCPE(eachNode)
                    #for eachCpe in eachNode.children:
                    #    print(eachCpe.cpe23Uri)
                    #print("...................................")
                for element in self.cpes:
                    for subelement in element:
                        if subelement.vulnerable:
                            #print(subelement.cpe23Uri)
                            if "linux_kernel" in subelement.cpe23Uri:
                                falsepositive = False
                    #print("CPE: ", element)
                #print("...................................")
                ### Part 2: Elements without Children
                for eachCpe in eachNode.cpe_match:
                    #print(eachCpe.cpe23Uri)
                    #TODO: check for vulnerable==true as in part1
                    pass

            if falsepositive:
                falsepositivelist.append(cve.id)
                print(" #### FALSE POSITIVE ####")
            else:
                ncve = CVE(cve)
                truecvelist.append(ncve)
                self.cves.append(ncve)
                print()

        print("------------- CVE Download complete -------------")
        print("Results:", len(r))
        print("Results w/o false positives:", len(truecvelist))
        print("False positives:", len(falsepositivelist))

        cvelist.sort()
        falsepositivelist.sort()
        

    def extractpath(self, cvedescr:str) -> str:
        """Tries to extract a c-file path from a cve description"""
        ret = ""
        pat = r"[a-zA-Z0-9-_/]*(\.c)"
        strmatch = re.search(pat, cvedescr)
        if strmatch:
            logging.info("Extracted path: " + strmatch[0])
            ret = strmatch[0]

        return ret

    def __false_positive(self):
        """Check for false positive. Note: This is a oversimplified check. It only checks for non-linux-kernel cpes and ignores the CPE logic, i.e. does not parse the tree."""
        pass

    def print(self):
        #
        # CVE id 
        # CVE url
        # CVE date
        # CVE score v3
        # CVE description
        # identified dependency (flag)
        # identified dependency (arch)
        # check result (applicability)
        # config check result
        # config reference
        pass

    def export(self, format):
        pass

    def export_xlsx(self, export_path:str):
        """Export to a xslx File"""
        
        logging.info("Exporting results to " + export_path)

        workbook = xlsxwriter.Workbook(export_path)
        cve_worksheet = workbook.add_worksheet('CVEs')
        meta_worksheet = workbook.add_worksheet('Metadata')

        row = 0
        col = 0
        header = ['CVE ID','CVSSv2','CVSSv3','URL','Description','Result','Confidence','Reason','Flag','Source Path']
        cve_worksheet.write_row(row, col, header)
        row += 1
        for resitem in self.results:
            header = ['CVE ID','CVSSv2','CVSSv3','URL','Description','Result','Confidence','Reason','Flag','Source Path']
            restext = ""
            certtext = ""
            if resitem.result == self.CHECK_CVE_APPLICABLE:
                restext = "APPLICABLE"
            elif resitem.result == self.CHECK_CVE_NOT_APPLICABLE:
                restext = "NOT APPLICABLE"
            elif resitem.result == self.CHECK_INCONCLUSIVE:
                restext = "INCONCLUSIVE"
            
            certtext = "! LOW !" if resitem.isUncertain else "OK"
            rr = ResultReason()
            reasontext = rr.getText(resitem.reason)

            entry = {'id': resitem.cve.id , 'CVSSv2': resitem.cve.CVSSv2, 'CVSSv3': resitem.cve.CVSSv3, 'URL': resitem.cve.url, 'description': resitem.cve.description, 'result': restext, 'confidence': certtext, 'reason':reasontext, 'flag': resitem.flag, 'path': resitem.path }
            entryval = list(entry.values())
            cve_worksheet.write_row(row, col, entryval)
            row += 1


        workbook.close()




def setup_directories():
    """Creates Working Directories if necessary"""
    # TODO: add dir setup
    pass



def main():
    global NIST_NVD_API_KEY, KERNEL_SRC_DIR, KERNEL_VERSION, KERNEL_ARCH, KERNEL_CONFIG_FILE, CONSOLE_COLOR

    logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.DEBUG)

    colorama.init()

    
    config = configparser.ConfigParser()
    config.read('licc.ini')
    # TODO: Cmdline options
    # TODO: cmdline: config path


    try:
        NIST_NVD_API_KEY = config['NIST']['APIKEY'].strip('"')
        KERNEL_SRC_DIR = config['dirs']['KERNEL_SRC_DIR'].strip('"')
        KERNEL_VERSION = config['kernel']['KERNEL_VERSION'].strip('"')
        KERNEL_ARCH = config['kernel']['KERNEL_ARCH'].strip('"')
        KERNEL_CONFIG_FILE = config['kernel']['KERNEL_CONFIG_FILE'].strip('"')
        CONSOLE_COLOR = bool(config['console']['CONSOLE_COLOR'].strip('"'))

    except KeyError as e:
        print("Error loading config, using defaults.")
        

    setup_directories()

    cvem = CVEManager()
    
    #
    # Step 1: Check if Source is available and download if not
    # Step 2a: Get CVEs
    cvem.update_cves()
    # Step 2b: Filter for False-Positives
    # Step 2c (opt): Filter according to e.g. Score, CWE, Publish-Date, Mod-Date
    # Step 3: iterate over CVEs, check for applicability
    cvem.check_cves()
    # Step 4: Store Results
    cvem.export_xlsx('export.xlsx')
    #TODO: export path from config

if __name__ == "__main__":
    main()