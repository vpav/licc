# licc - Linux CVE Check

A lot of Linux vulnerabilities are located in a particular driver or subsystem, i.e. only afffect kernels with a particular configuration. Checking things manually is a tedious task, therefore licc aims to automatically check which CVEs apply to a particular kernel version and config.

licc takes the following **inputs** to work:

* the kernel version
* your kernel config
* the system cpu architecture
* (optionally) the kernel source

from these inputs, licc checks the NVD database and crosschecks all retrieved vulnerabilities for applicability for the specific kernel and **generates a report**.

In case you don't supply a custom source, licc will automatically fetch the kernel source for the supplied kernel version from kernel.org.

# basic usage

## 0. setup

You can skip this part if you are familiar with running python scripts.

### Install python 3.9

### Clone repository:
    git clone https://github.com/vpav/licc

### cd to licc and install required python modules
    cd licc
    pip install -r requirements.txt

## 1. prepare the config-file

Edit the example licc.ini.

All the following lines are expected to be present in the file.


```ini
[dirs]
# the base directory where licc will save downloaded kernel sources to
# each downloaded kernel takes ~500MB of space
KERNEL_SRC_DIR = /home/liccusr/local_data/kernel_source/

[kernel]
# edit parameters for the kernel you which to analyze
# KERNEL_CONFIG_FILE should point to the kernels build configuration
KERNEL_CONFIG_FILE = /path/to/your/kernel-config-5.4.0-122-generic
KERNEL_VERSION = "4.14.290"
KERNEL_ARCH = "aarch64"

[NIST]
# NIST NVD API Key
# Leave value empty if you don't have a key, requests will be slower though
APIKEY = 12345678-90ab-cdef-fedc-ba0987654321  

[console]
# enable colored output - you might want to disable this if you 
# are piping to a log file
CONSOLE_COLOR = True
```

### Kernel settings

These are your input parameters wich will change for every unique kernel you like to analyze. Provide the path to your kernel config file, your kernel version and the system architecture (x86, x64, ...).

### NIST NVD API Key

You don't need a [NIST API key](https://nvd.nist.gov/developers/request-an-api-key) but it is recommended as it will allow for faster CVE lookups. If you don't have an API key, leave the setting present but empty: `APIKEY = `

## 2. run licc

```
python licc.py
```

# command line options

You can overwrite some of the settings using command-line options.

### use different licc config

By default, licc loads `./licc.ini`. If you want to work with multiple, preconfigured kernels you can change the config with

```
python licc.py --lconfig /path/to/a/different_config.ini
```

### overwrite kernel settings

You can manually override one or more of the kernel specific-settings:
```
python licc.py --kversion 3.18.144 --arch arm32 --kconfig /path/to/my/3.18-config
```

### report settings

licc currently supports reports as **csv** or **xlsx** files.

By default, licc creates a CSV report and saves it to `./export.csv`

You can supply format and location:

```
python licc.py --out kernel-3.18.xslx --outformat xls
```


# vanilla vs. non-vanilla kernel

If you are using a *vanilla kernel*, i.e. an unmodified kernel using only the official sources from kernel.org, licc can automatically download the kernel source for you (default behavior)

If you are using a *customized kernel*, i.e. a modified kernel with code parts that are not available upstream, Richard Stallman is obviously not amused and puts you on his naughty-list. Nevertheless, you can specify the kernel sources manually:

```
python licc.py --src /path/to/my/custom/kernelsrc/
```

# understanding the report

licc will list all vulnerabilities that apply to the supplied kernel version in general. For each of those, licc will give three relevant statements:

* verdict
* confidence
* reason

## verdict

* **APPLICABLE** - The vulnerability applies to the specified kernel & config
* **NOT APPLICABLE** - The vulnerability does not apply to the specified kernel & config
* **INCONCLUSIVE** - Licc does not make a statement about applicability, i.e. you need to check 

## confidence

As some checks are not working precisely (yet) licc provides you with a statement about the result confidence, indicating low-confidence statements.

## reason

If a statement is given, the reason is outlined.

# where do I get the kernel config from?

licc is primarily developed for people who are configuring and integrating kernels for their projects. I.e. those who compile the kernel. 
In these cases your kernel config is the result of  `make menuconfig`, `make config` or what ever flavor of make process you are using.

If you like to use licc to check a kernel you have not built yourself, you can check if one of the following files is present in your system:

* `/proc/config.gz`
* `/boot/config`
* `/boot/config-${kernel-version}`

If present, that file is your kernel build config. **Note:** licc expects the config in plaintext, so in case of the first option you'd need to extract first:

```
zcat /proc/config.gz > kernelbuildconfig.txt
```

# known issues and limitations

- as there is no formal way how components and subsystems are identified within the CVE/CPE system (i.e. it only sees the kernel is an atomic entity), therefore the matching currently only works on such vulnarabilities that mention a particular source file
- the CPE matching is lazily written it is possible that CVEs are included that are not affecting your kernel or any kernel at all
- kernel architecture is not considered yet
- the makefile parsing is also lazily written and does not account for conditional statements (`ifeq`) yet. The user is warned though via a low confidence indication, if such makefile is encountered.