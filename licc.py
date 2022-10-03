from ast import Str
from distutils.command.build_scripts import first_line_re
from genericpath import isfile
from inspect import currentframe
import os
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
import csv
import colorama
import sys
import requests
import shutil
from tqdm import tqdm
import functools
import tarfile
import argparse


#
# Tool Settings
#
KERNEL_SRC_DIR = ""
TMP_DIR = ""
KERNEL_SRC_BASE_URL = "https://mirrors.edge.kernel.org/pub/linux/kernel/v{major}.x/linux-{major}.{minor}.{build}.tar.xz"
KERNEL_LOCAL_FILENAME = "linux-{major}.{minor}.{build}.tar.xz"
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
        subdir = "linux-" + kversion
        self.root_path = os.path.join(KERNEL_SRC_DIR, subdir)
        logging.info("Source Checker initialized for Kernel " + kversion)

    def __download_src(self) -> Str:
        
        kvers = KERNEL_VERSION.split(".")

        k_major = kvers[0]
        k_minor = kvers[1]
        k_build = kvers[2]

        kurl = KERNEL_SRC_BASE_URL.replace("{major}", k_major).replace("{minor}", k_minor).replace("{build}", k_build)
        kfn = KERNEL_LOCAL_FILENAME.replace("{major}", k_major).replace("{minor}", k_minor).replace("{build}", k_build)
        kpath = os.path.join(KERNEL_SRC_DIR, kfn)

        req = requests.get(kurl, stream=True, allow_redirects=True)
        if req.status_code != 200:
            req.raise_for_status()

            if req.status_code == 404:
                logging.error("Error: Download of kernel source code failed, source not found in kernel archive")
            else:
                logging.error("Error: Download of kernel source code failed")    

            raise RuntimeError(f"Request to {kurl} returned status code {req.status_code}")
            
        file_size = int(req.headers.get('Content-Length', 0))

        path = pathlib.Path(kpath).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        desc = "(Unknown total file size)" if file_size == 0 else ""
        req.raw.read = functools.partial(req.raw.read, decode_content=True)  # Decompress if needed
        with tqdm.wrapattr(req.raw, "read", total=file_size, desc=desc) as r_raw:
            with path.open("wb") as f:
                shutil.copyfileobj(r_raw, f)

        return kpath
        

    def __extract_src(self, tarpath:Str):
        try:
            with tarfile.open(tarpath) as tfile:
                tfile.extractall(KERNEL_SRC_DIR)
        except (tarfile.TarError, IOError, OSError):
            logging.error("Error while extracting " + tarpath)
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
            logging.info("Kernel Source not found in cache, downloading...")
            # download
            tarxz = self.__download_src()
            # extract
            self.__extract_src(tarxz)
            # cleanup tmp (tarxz)
            logging.debug("Cleaning up...")
            try:
                os.remove(tarxz)
            except OSError:
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

    EXPORT_CSV = 0
    EXPORT_XLSX = 1

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

        arch = self.extractarch(cve.description)

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
        if "children" in iter:
            
            if iter.children:
                # Children contains elements
                a = []
                for child in iter.children:
                    self.collectCPE(child)   
            else:
                # Children contains NO elements
                self.cpes.append(iter.cpe_match)


    def update_cves(self):
        """Update local CVEs DB from NIST DB"""

        # user does NOT have api key: limit = 10 req / 60s
        # user has api key:  limit = 100 req / 60s
        r = nvdlib.searchCVE(cpeName = 'cpe:2.3:o:linux:linux_kernel:' + KERNEL_VERSION + ':*:*:*:*:*:*:*', key=NIST_NVD_API_KEY)
        cvelist = []
        truecvelist: list[CVE] = []
        falsepositivelist = []
        for cve in r:
            self.cpes = []
            
            print("-----------------------------------------------")
            print(cve.id, end='')
            cvelist.append(cve.id)
            config = cve.configurations.nodes

            falsepositive = self.__false_positive(config)

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

    def extractarch(self, cvedescr:str) -> str:
        """Tries to extract the architecture from a cve description"""
        arch = ""
        
        return arch

    def __false_positive(self, config) -> bool:
        """Check for false positive. Note: This is a oversimplified check. It only checks for non-linux-kernel cpes and ignores the CPE logic, i.e. does not parse the tree."""

        # Search the CPEs of retrieved CVE for real matches as the searchCVE() 
        # returns all CVEs that contain the linux CPE. 
        # CPEs are organized trees. In some cases CVEs include linux only as 
        # the OS of an application software containing the CVE.
        # 
        # BUG: This matching is lazily implemented. 
        # A real mathing would need to parse the entire tree.
        falsepositive = True

        for eachNode in config:
            ### Part 1: Elements with Children
            if "children" in eachNode:
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
        return falsepositive
        

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

    def export(self, export_path:str, format:int):
        if format == self.EXPORT_CSV:
            self.export_csv(export_path)
        elif format == self.EXPORT_XLSX:
            self.export_xlsx(export_path)
        else:
            raise ValueError()

    def export_xlsx(self, export_path:str):
        """Export to a xslx File"""
        
        logging.info("Exporting results as XLSX to " + export_path)

        workbook = xlsxwriter.Workbook(export_path)
        cve_worksheet = workbook.add_worksheet('CVEs')
        meta_worksheet = workbook.add_worksheet('Metadata')

        # TODO: add second worksheet with metadata

        #
        # Formatting
        header_format = workbook.add_format({'bold': True, 'font_color': '#ffffff', 'bg_color': '#303030'})
        inconclusive_format = workbook.add_format({'bold': True, 'font_color': '#606000', 'bg_color': '#FFFFC0'})
        na_format = workbook.add_format({'bold': True, 'font_color': '#204f35', 'bg_color': '#4ee895'})
        applicable_format = workbook.add_format({'bold': True, 'font_color': '#69383a', 'bg_color': '#e84e53'})
        warning_format = workbook.add_format({'bold': True, 'font_color': '#694f38', 'bg_color': '#e8964e'})
        header_height = 18 # cell height in pt


        #
        # Data Writing - Header
        row = 0
        col = 0
        header = ['CVE ID','CVSSv2','CVSSv3','URL','Description','Result','Confidence','Reason','Flag','Source Path']
        cve_worksheet.write_row(row, col, header, header_format)
        cve_worksheet.set_row(row, header_height, header_format)
        row += 1
        #
        # Data Writing - CVEs
        cve_worksheet.set_column(0,0,20) # cve-id
        cve_worksheet.set_column(4,4,60) # descirption
        cve_worksheet.set_column(5,5,20) # result
        cve_worksheet.set_column(5,5,15) # confidence
        
        for resitem in self.results:
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

            # apply content dependent formatting
            # formats cannot be applied to cells afterwards, therefore we overwrite the cell
            if resitem.result == self.CHECK_CVE_APPLICABLE:
                cve_worksheet.write(row, 5, entry['result'], applicable_format ) 
            elif resitem.result == self.CHECK_CVE_NOT_APPLICABLE:
                cve_worksheet.write(row, 5, entry['result'], na_format ) 
            elif resitem.result == self.CHECK_INCONCLUSIVE:
                cve_worksheet.write(row, 5, entry['result'], inconclusive_format ) 
            if resitem.isUncertain:
                cve_worksheet.write(row, 6, entry['confidence'], warning_format ) 

            row += 1


        workbook.close()

    def export_csv(self, export_path:str):
        """Export to a csv File"""

        header = ['CVE ID','CVSSv2','CVSSv3','URL','Description','Result','Confidence','Reason','Flag','Source Path']

        with open(export_path, 'w', newline='') as csvfile:
            cvewriter = csv.writer(csvfile, delimiter=';',
                                    quotechar='|', quoting=csv.QUOTE_MINIMAL)
            
            cvewriter.writerow(header)
            for resitem in self.results:
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
                cvewriter.writerow(entryval)

        logging.info("Exporting results as CSV to " + export_path)




def setup_directories():
    """Creates Working Directories if necessary"""
    # TODO: add dir setup
    try:
        if os.path.exists(KERNEL_SRC_DIR):
            os.mkdir(KERNEL_SRC_DIR)
    except (OSError, IOError):
        logging.error("Error creating working directories")
        
    



def main():
    global NIST_NVD_API_KEY, KERNEL_SRC_DIR, KERNEL_VERSION, KERNEL_ARCH, KERNEL_CONFIG_FILE, CONSOLE_COLOR

    logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.DEBUG)

    colorama.init()

    descr_default = """ __         __     ______     ______    
/\ \       /\ \   /\  ___\   /\  ___\   
\ \ \____  \ \ \  \ \ \____  \ \ \____  
 \ \_____\  \ \_\  \ \_____\  \ \_____\ 
  \/_____/   \/_/   \/_____/   \/_____/

  licc - linux cve checker

  Copyright 2022 Viktor Pavlovic

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see http://www.gnu.org/licenses/"""

    descr_color = colorama.Fore.LIGHTCYAN_EX + """ __         __     ______     ______    
/\ \       /\ \   /\  ___\   /\  ___\   
\ \ \____  \ \ \  \ \ \____  \ \ \____  
 \ \_____\  \ \_\  \ \_____\  \ \_____\ 
  \/_____/   \/_/   \/_____/   \/_____/ 

""" + colorama.Style.RESET_ALL + """  licc - """ + colorama.Fore.LIGHTRED_EX + "li" + colorama.Style.RESET_ALL + "nux " + colorama.Fore.LIGHTRED_EX + "c" + colorama.Style.RESET_ALL + "ve " + colorama.Fore.LIGHTRED_EX + "c" + colorama.Style.RESET_ALL + """hecker

  Copyright 2022 Viktor Pavlovic

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see http://www.gnu.org/licenses/"""

    parser = argparse.ArgumentParser(description=descr_color,formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-l','--lconfig', metavar='PATH', type=pathlib.Path, help='licc config to use, defaults to ./licc.ini')
    parser.add_argument('-c','--kconfig', metavar='PATH', type=pathlib.Path, help='kernel config path')
    parser.add_argument('-o', '--out', metavar='PATH', help='report path')
    parser.add_argument('-f', '--outformat', metavar='XLS|CSV', help='report format')
    parser.add_argument('-s', '--src', metavar='PATH', type=pathlib.Path, help='kernel source directory. Overwrites default search path & auto-download, use if you want to work with your (non-vanilla) kernel code')
    parser.add_argument('-t', '--type') # unused
    parser.add_argument('-v', '--kversion', help='kernel version to check')
    parser.add_argument('-a', '--arch', help='kernel arch')


    args = parser.parse_args()

    if args.out:
        outfile = args.out
    else:
        if args.outformat == "xls":
            outfile = 'export.xslx'
        elif args.outformat == "csv":
            outfile = 'export.csv'
        else:
            outfile = 'export.csv'


    if args.outformat:
        if str(args.outformat).lower() == "xls" or str(args.outformat).lower() == "xlsx":
            outfmt = CVEManager.EXPORT_XLSX
        elif str(args.outformat).lower() == "csv":
            outfmt = CVEManager.EXPORT_CSV
        else:
            logging.info("Invalid report format specified, defaulting to CSV")
            outfmt = CVEManager.EXPORT_CSV
    else:
        outfmt = CVEManager.EXPORT_CSV

    if args.lconfig:
        licc_config = args.licc
    else:
        licc_config = 'licc.ini'
    

    config = configparser.ConfigParser()
    config.read(licc_config)

    try: 
        NIST_NVD_API_KEY = config['NIST']['APIKEY'].strip('"')
        if NIST_NVD_API_KEY == "":
            logging.warning("No NIST API Key supplied, NIST Lookup will be slower.")
    except KeyError as e:
        logging.error("Error NIST API Key, using defaults.")   
        NIST_NVD_API_KEY = ""

    try:
        
        KERNEL_SRC_DIR = config['dirs']['KERNEL_SRC_DIR'].strip('"')
        KERNEL_VERSION = config['kernel']['KERNEL_VERSION'].strip('"')
        KERNEL_ARCH = config['kernel']['KERNEL_ARCH'].strip('"')
        KERNEL_CONFIG_FILE = config['kernel']['KERNEL_CONFIG_FILE'].strip('"')
        CONSOLE_COLOR = bool(config['console']['CONSOLE_COLOR'].strip('"'))

    except KeyError as e:
        print("Error loading config, using defaults.")
        
    if args.kversion:
        logging.info("Using cmdline supplied kernel version instead of config")
        KERNEL_VERSION = args.kversion

    if args.arch:
        logging.info("Using cmdline supplied kernel arch instead of config")
        KERNEL_ARCH = args.arch

    setup_directories()

    # plausibility check for kverson
    ar = re.match(r"\d{1,1}\.\d{1,2}\.\d{1,3}", KERNEL_VERSION)
    if not ar:
        logging.warning("Warning: Configured Kernel Version seems unplausible: " + KERNEL_VERSION)
    
    # plausibility check for arch
    if not KERNEL_ARCH in ["aarch64", "aarch32", "x86", "x64", "x86_64", "ia64", "alpha", "riscv", "openrisc" "s390", "mips", "powerpc","m68k"]:
        logging.warning("Warning: Configured Kernel Architecture seems unplausible: " + KERNEL_ARCH)

    # normalize kernel arch
    if KERNEL_ARCH in ["aarch64", "arm64"]:
        KERNEL_ARCH = "arm64"
    elif KERNEL_ARCH in ["aarch32", "arm", "arm32"]:
        KERNEL_ARCH = "arm"
    elif KERNEL_ARCH in ["x64", "x86_64", "ia64"]:
        KERNEL_ARCH = "ia64"

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
    cvem.export(outfile, outfmt)

if __name__ == "__main__":
    main()