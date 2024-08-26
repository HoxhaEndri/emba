#!/bin/bash -p
# see: https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html#//apple_ref/doc/uid/TP40004268-CH8-SW29

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Endri Hoxha

# Description:  Update script for Snyk Exploit/PoC collection


URL="https://security.snyk.io/vuln"
LINKS="snyk_adv_links.txt"
SAVE_PATH="/tmp/snyk"
EMBA_CONFIG_PATH="./config/"

if ! [[ -d "${EMBA_CONFIG_PATH}" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if [[ -f "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv ]]; then
  PoC_CNT_BEFORE="$(wc -l "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv | awk '{print $1}')"
  echo -e "${GREEN}[+] Found ${ORANGE}${PoC_CNT_BEFORE}${GREEN} advisories with PoC code (before udpate)"
fi

if [[ -d "${SAVE_PATH}" ]]; then
  rm -r "${SAVE_PATH}"
fi
if ! [[ -d "${SAVE_PATH}/vuln" ]]; then
  mkdir -p "${SAVE_PATH}/vuln"
fi

echo "[*] Generating URL list for snyk advisories"
ID=1
# this approach will end after 31 pages:
while lynx -useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.79 Safari/537.1" -dump -hiddenlinks=listonly "${URL}"/"${ID}" | grep "${URL}/SNYK" >> "${SAVE_PATH}"/"${LINKS}"; do
  echo -e "[*] Generating list of URLs of Snyk advisory page ${ORANGE}${ID}${NC} / ${ORANGE}${URL}${ID}${NC}"
  ((ID+=1))
done

# some filters we can use to get further results:
APPLICATIONS=("cargo" "cocoapods" "composer" "golang" "hex" "maven" "npm" "nuget" "pip" \
  "rubygems" "unmanaged" "linux" "alpine" "amzn" "centos" "debian" "oracle" "rhel" \
  "sles" "ubuntu")

for APPLICATION in "${APPLICATIONS[@]}"; do
  ID=1
  while lynx -useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.79 Safari/537.1" -dump -hiddenlinks=listonly "${URL}"/"${APPLICATION}"/"${ID}" | grep "${URL}/SNYK" >> "${SAVE_PATH}"/"${LINKS}"; do
    echo -e "[*] Generating list of URLs of Snyk advisory page ${ORANGE}${ID}${NC} / application ${ORANGE}${APPLICATION}${NC} / URL ${ORANGE}${URL}/${APPLICATION}/${ID}${NC}"
    ((ID+=1))
  done
done

# as we do not reach all the advisories via this search mechanism we also load the current state
# and use the URLs from it for further crawling:
if [[ -f "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv ]]; then
  echo -e "[*] Adding already knwon URLs from current configuration file"
  cut -d\; -f3 "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv >> "${SAVE_PATH}"/"${LINKS}"
else
  echo -e "${RED}[-] WARNING: No Snyk configuration file found"
fi

# remove the numbering at the beginning of every entry:
tail -n +2 "${SAVE_PATH}"/"${LINKS}" | sed 's/.*http/http/' | sort -u > "${SAVE_PATH}"/"${LINKS}"_sorted

ADV_CNT="$(wc -l "${SAVE_PATH}"/"${LINKS}"_sorted | awk '{print $1}')"
echo -e "[*] Detected ${ORANGE}${ADV_CNT}${NC} advisories for download"
echo ""

python scraper.py "${SAVE_PATH}"/"${LINKS}"_sorted "${SAVE_PATH}"/Snyk_PoC_results.csv
sort -nr -o "${SAVE_PATH}"/Snyk_PoC_results.csv "${SAVE_PATH}"/Snyk_PoC_results.csv

if [[ -f "${SAVE_PATH}"/Snyk_PoC_results.csv ]] && [[ -d "${EMBA_CONFIG_PATH}" ]]; then
  uniq "${SAVE_PATH}"/Snyk_PoC_results.csv > "${EMBA_CONFIG_PATH}"/Snyk_PoC_results.csv
  rm -r "${SAVE_PATH}"
  echo -e "${GREEN}[+] Successfully stored generated PoC file in EMBA configuration directory."
else
  echo "[-] Not able to copy generated PoC file to configuration directory ${EMBA_CONFIG_PATH}"
fi
