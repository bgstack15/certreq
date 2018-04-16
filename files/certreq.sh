#!/bin/sh
# Filename: certreq.sh
# Location: atower201:/etc/ansible/roles/certreq/files/certreq.sh
# Author: bgstack15@gmail.com
# Startdate: 2017-11-17 09:13:53
# Title: Script that Requests a Certificate from a Microsoft Sub-CA
# Purpose: Automate host certificate generation in a domain environment
# Package: ansible role certreq
# History: 
#    2017-11-22 Add ca cert chain
#    2018-04-16 Add --list and --csr options
# Usage: in ansible role certreq
#    Microsoft CA cert templates have permissions on them. A user must be able to "enroll" on the template.
# Reference: ftemplate.sh 2017-10-10x; framework.sh 2017-10-09a
#    fundamental curl statements https://stackoverflow.com/questions/31283476/submitting-base64-csr-to-a-microsoft-ca-via-curl/39722983#39722983
# Improve:
fiversion="2017-10-10x"
certreqversion="2018-04-16a"

usage() {
   less -F >&2 <<ENDUSAGE
usage: certreq.sh [-dhV] [-u username] [-p password] [-w tempdir] [-t template] [--cn CN] [--ca <CA hostname>] [-l|-g]
version ${certreqversion}
 -d debug   Show debugging info, including parsed variables.
 -h usage   Show this usage block.
 -V version Show script version number.
 -u username User to connect via ntlm to CA. Can be "username" or "domain\\username"
 -p password
 -w workdir  Temp directory to work in. Default is \$(mktemp -d).
 -t template Template to request from CA. Default is "ConfigMgrLinuxClientCertificate"
 --cn        CN to request. Default is \$( hostname -f )
 --ca        CA hostname or base URL. Example: ca2.example.com
 --list      Action: list available templates and exit.
Return values under 1000: A non-zero value is the sum of the items listed here:
 0 Everything worked
 1 Cert file is still a CSR
 2 Cert file is html, probably due to permissions/credentials issue
 4 Return code of curl statement that saves cert file is non-zero
 8 Cert file does not contain whole certificate
16 Cert does not contain an issuer
Return values above 1000:
1001 Help or version info displayed
1002 Count or type of flaglessvals is incorrect
1003 Incorrect OS type
1004 Unable to find dependency
1005 Not run as root or sudo
ENDUSAGE
}

# DEFINE FUNCTIONS

openssl_req() {
   # call: openssl-req "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}"
   # outputs:
   #    vars: ${CERT} ${DATA} ${CERTATTRIB}
   #    files: ${CERTREQ_WORKDIR}/${this_filename}.crt ${CERTREQ_WORKDIR}/${thisfilename}.key

   local this_filename="${1}"
   local this_subject="${2}"
   
   openssl req -new -nodes \
      -out "${CERTREQ_WORKDIR}/${this_filename}.crt" \
      -keyout "${CERTREQ_WORKDIR}/${this_filename}.key" \
      -subj "${this_subject}"
   CERT="$( cat "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" | tr -d '\n\r' )"
   DATA="Mode=newreq&CertRequest=${CERT}&C&TargetStoreFlags=0&SaveCert=yes"
   CERT="$( echo ${CERT} | sed -e 's/+/%2B/g' | tr -s ' ' '+' )"
   CERTATTRIB="CertificateTemplate:${CERTREQ_TEMPLATE}"

}

submit_csr() {
   # call: submit_csr "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERT}" "${CERTATTRIB}"
   # outputs: ${CERTLINK}

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"
   local this_cert="${4}"
   local this_cert_attrib="${5}"

   OUTPUTLINK="$( curl -k -u "${this_user_string}" --ntlm \
      "${this_ca}/certsrv/certfnsh.asp" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      --data "Mode=newreq&CertRequest=${this_cert}&CertAttrib=${CERTATTRIB}&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" | grep -A 1 'function handleGetCert() {' | tail -n 1 | cut -d '"' -f 2 )"
   CERTLINK="${this_ca}/certsrv/${OUTPUTLINK}"

}

fetch_signed_cert() {
   # call: fetch_signed_cert "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CERTLINK}" "${CERTREQ_CNPARAM}"
   # output:
   #    vars: ${finaloutput}
   #    files: ${CERTREQ_WORKDIR}/${this_filename}.crt

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"
   local this_certlink="${4}"
   local this_filename="${5}"

   curl -k -u "${this_user_string}" --ntlm "${this_certlink}" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' > "${CERTREQ_WORKDIR}/${this_filename}.crt"
   finaloutput=$?

}

get_number_of_current_ca_cert() {
   # call: get_number_of_current_ca_cert "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
   # outputs: ${CURRENTNUM}

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"

   RESPONSE="$( curl -s -k -u "${this_user_string}" --ntlm \
      "${this_ca}/certsrv/certcarc.asp" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' )"
   CURRENTNUM="$( echo "${RESPONSE}" | grep -cE 'Option' )"

}

get_latest_ca_cert_chain() {
   # call: get_latest_ca_cert_chain "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}" "${CURRENTNUM}"
   # outputs:
   #    files: ${CHAIN_FILE}

   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"
   local this_num="${4}"

   CURRENT_P7B="$( curl -s -k -u "${this_user_string}" --ntlm \
      "${this_ca}/certsrv/certnew.p7b?ReqID=CACert&Renewal=${this_num}" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqxt.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' )"

   # CONVERT TO PEM
   echo "${CURRENT_P7B}" | openssl pkcs7 -print_certs -out "${CERTREQ_TEMPFILE}"

   # RENAME TO PROPER FILENAME
   # will read only the first cert, so get domain of issuer of it.
   CA_DOMAIN="$( openssl x509 -in "${CERTREQ_TEMPFILE}" -noout -issuer 2>&1 | sed -r -e 's/^.*CN=[A-Za-z0-9]+\.//;' )"
   CHAIN_FILE="chain-${CA_DOMAIN}.crt"
   mv -f "${CERTREQ_TEMPFILE}" "${CERTREQ_WORKDIR}/${CHAIN_FILE}" 1>/dev/null 2>&1

}

action_get_cert() {
   # call: action_get_cert "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
   # outputs:
   #   vars: ${finaloutput}
   #   files: ${CHAIN_FILE} ${CERTREQ_CNPARAM}.crt and .key and 

   local this_cnparam="${1}"
   local this_subject="${2}"
   local this_user_string="${3}"
   local this_ca="${4}"
   local this_ca_host="${5}"

   # GENERATE PRIVATE KEY
   openssl_req "${this_cnparam}" "${this_subject}"
   debuglev 1 && {
      # DELETEME
      echo "CERT=${CERT}"
      echo "DATA=${DATA}"
      echo "CERTATTRIB=${CERTATTRIB}"
   } 

   # SUBMIT CERTIFICATE SIGNING REQUEST 
   submit_csr "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CERT}" "${CERTATTRIB}"
   debuglev 1 && {
      # DELETEME
      echo "CERTLINK=${CERTLINK}"
   }

   # FETCH SIGNED CERTIFICATE
   fetch_signed_cert "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CERTLINK}" "${this_cnparam}"
   debuglev 1 && {
      echo "finaloutput=${finaloutput}"
   }

   # GET NUMBER OF CURRENT CA CERT
   get_number_of_current_ca_cert "${this_user_string}" "${this_ca}" "${this_ca_host}"
   debuglev 1 && {
      echo "CURRENTNUM=${CURRENTNUM}"
   }

   # GET LATEST CA CERT CHAIN
   get_latest_ca_cert_chain "${this_user_string}" "${this_ca}" "${this_ca_host}" "${CURRENTNUM}"
   debuglev 1 && {
      echo "CHAIN_FILE=${CHAIN_FILE}"
   }

}

action_list_templates() {
   # call: action_list_templates "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
   
   local this_user_string="${1}"
   local this_ca="${2}"
   local this_ca_host="${3}"

   RESPONSE="$( curl -s -k -u "${this_user_string}" --ntlm \
      "${this_ca}/certsrv/certrqxt.asp" \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
      -H 'Accept-Encoding: gzip, deflate' \
      -H 'Accept-Language: en-US,en;q=0.5' \
      -H 'Connection: keep-alive' \
      -H "Host: ${this_ca_host}" \
      -H "Referer: ${this_ca}/certsrv/certrqus.asp" \
      -H 'User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko' \
      -H 'Content-Type: application/x-www-form-urlencoded' )"
   AVAILABLE_TEMPLATES="$( echo "${RESPONSE}" | grep -E -- "<Option" | grep -oE "Value=\".*\">" |awk -F';' -v 'a=0' 'BEGIN{OFS=","} {a=a+1; print a,$2,$14}' | sed -r -e 's/">\s*$//;' )"
   # goal: set a variable of the items, probably comma-delimited

}

# DEFINE TRAPS

clean_certreq() {
   # use at end of entire script if you need to clean up tmpfiles
   #rm -f ${tmpfile} 1>/dev/null 2>&1
   if test -z "${CR_NC}";
   then
      nohup /bin/bash <<EOF 1>/dev/null 2>&1 &
sleep "${CERTREQ_CLEANUP_SEC:-300}" ; /bin/rm -r "${CERTREQ_WORKDIR}" 2>/dev/null ;
EOF
#sleep "${CERTREQ_CLEANUP_SEC:-300}" ; /bin/rm -r "${CERTREQ_WORKDIR}" 2>/dev/null ; echo "slash-dollar-0=\"\$0\"  slash-slash-dollar-0=\"\\$0\"" > /dev/pts/2 ;
   fi

}

CTRLC() {
   # use with: trap "CTRLC" 2
   # useful for controlling the ctrl+c keystroke
   :
}

CTRLZ() {
   # use with: trap "CTRLZ" 18
   # useful for controlling the ctrl+z keystroke
   :
}

parseFlag() {
   flag="$1"
   hasval=0
   case ${flag} in
      # INSERT FLAGS HERE
      "d" | "debug" | "DEBUG" | "dd" ) setdebug; ferror "debug level ${debug}";;
      "usage" | "help" | "h" ) usage; exit 1001;;
      "V" | "fcheck" | "version" ) ferror "${scriptfile} version ${certreqversion}"; exit 1001;;
      "u" | "user" | "username" ) getval; CERTREQ_USER="${tempval}";;
      "p" | "pass" | "password" ) getval; CERTREQ_PASS="${tempval}";;
      "w" | "work" | "workdir" ) getval; CERTREQ_WORKDIR="${tempval}";;
      "t" | "temp" | "template" ) getval; CERTREQ_TEMPLATE="${tempval}";;
      "cn" | "common-name" | "commonname" ) getval; CERTREQ_CNPARAM="${tempval}";;
      "ca" | "certauthority" | "cauthority" ) getval; CERTREQ_CAPARAM="${tempval}";;
      "c" | "conf" | "conffile" | "config" ) getval; conffile="${tempval}";;
      "nc" | "nocleanup" ) CR_NC=1;;
      "l" | "list" ) CERTREQ_ACTION="list";;
      "g" | "generate" ) CERTREQ_ACTION="generate";;
   esac
   
   debuglev 10 && { test ${hasval} -eq 1 && ferror "flag: ${flag} = ${tempval}" || ferror "flag: ${flag}"; }
}

# DETERMINE LOCATION OF FRAMEWORK
while read flocation; do if test -f ${flocation} && test "$( sh ${flocation} --fcheck )" -ge 20170608; then frameworkscript="${flocation}"; break; fi; done <<EOFLOCATIONS
./framework.sh
${scriptdir}/framework.sh
/tmp/framework.sh
/usr/share/bgscripts/framework.sh
EOFLOCATIONS
test -z "${frameworkscript}" && echo "$0: framework not found. Aborted." 1>&2 && exit 1004

# INITIALIZE VARIABLES
# variables set in framework:
# today server thistty scriptdir scriptfile scripttrim
# is_cronjob stdin_piped stdout_piped stderr_piped sendsh sendopts
. ${frameworkscript} || echo "$0: framework did not run properly. Continuing..." 1>&2
infile1=
outfile1=
#logfile=${scriptdir}/${scripttrim}.${today}.out # defined farther down
define_if_new interestedparties "bgstack15@gmail.com"
# SIMPLECONF
define_if_new default_conffile "/tmp/certreq.conf"
define_if_new defuser_conffile ~/.config/certreq/certreq.conf

# REACT TO OPERATING SYSTEM TYPE
case $( uname -s ) in
   Linux) [ ];;
   *) echo "${scriptfile}: 3. Indeterminate OS: $( uname -s )" 1>&2 && exit 1003;;
esac

## REACT TO ROOT STATUS
#case ${is_root} in
#   1) # proper root
#      [ ] ;;
#   sudo) # sudo to root
#      [ ] ;;
#   "") # not root at all
#      #ferror "${scriptfile}: 5. Please run as root or sudo. Aborted."
#      #exit 1005
#      [ ]
#      ;;
#esac

# SET CUSTOM SCRIPT AND VALUES
#setval 1 sendsh sendopts<<EOFSENDSH      # if $1="1" then setvalout="critical-fail" on failure
#/usr/share/bgscripts/send.sh -hs     #                setvalout maybe be "fail" otherwise
#/usr/local/bin/send.sh -hs               # on success, setvalout="valid-sendsh"
#/usr/bin/mail -s
#EOFSENDSH
#test "${setvalout}" = "critical-fail" && ferror "${scriptfile}: 4. mailer not found. Aborted." && exit 1004

# VALIDATE PARAMETERS
# objects before the dash are options, which get filled with the optvals
# to debug flags, use option DEBUG. Variables set in framework: fallopts
validateparams - "$@"

# CONFIRM TOTAL NUMBER OF FLAGLESSVALS IS CORRECT
#if test ${thiscount} -lt 2;
#then
#   ferror "${scriptfile}: 2. Fewer than 2 flaglessvals. Aborted."
#   exit 1002
#fi

# LOAD CONFIG FROM SIMPLECONF
# This section follows a simple hierarchy of precedence, with first being used:
#    1. parameters and flags
#    2. environment
#    3. config file
#    4. default user config: ~/.config/script/script.conf
#    5. default config: /etc/script/script.conf
if test -f "${conffile}";
then
   get_conf "${conffile}"
else
   if test "${conffile}" = "${default_conffile}" || test "${conffile}" = "${defuser_conffile}"; then :; else test -n "${conffile}" && ferror "${scriptfile}: Ignoring conf file which is not found: ${conffile}."; fi
fi
test -f "${defuser_conffile}" && get_conf "${defuser_conffile}"
test -f "${default_conffile}" && get_conf "${default_conffile}"

# CONFIGURE VARIABLES AFTER PARAMETERS
define_if_new CERTREQ_USER "ANONYMOUS"
define_if_new CERTREQ_PASS "NOPASSWORD"
test -z "${CERTREQ_WORKDIR}" && CERTREQ_WORKDIR="$( mktemp -d )"
define_if_new CERTREQ_TEMPLATE "ConfigMgrLinuxClientCertificate"
define_if_new CERTREQ_CNLONG "$( hostname -f )"
define_if_new CERTREQ_CNSHORT "$( echo "${CERTREQ_CNLONG%%.*}" )"
define_if_new CERTREQ_CLEANUP_SEC 300
logfile="$( TMPDIR="${CERTREQ_WORKDIR}" mktemp -t tmp.XXXXXXXXXX )"
CERTREQ_TEMPFILE="$( TMPDIR="${CERTREQ_WORKDIR}" mktemp -t tmp.XXXXXXXXXX )"
define_if_new CERTREQ_ACTION "generate"

# calculate the subject
if test -n "${CERTREQ_CNPARAM}";
then
   # ensure good CN format.
   CERTREQ_CNPARAM="$( echo "${CERTREQ_CNPARAM}" | sed -r -e 's/^CN=//i;' )"
   case "${CERTREQ_CNPARAM}" in
      "${CERTREQ_CNLONG}" | "${CERTREQ_CNSHORT}" ) : ;;
      *) ferror "Using custom CN \"${CERTREQ_CNPARAM}\"" ;;
   esac
else
   CERTREQ_CNPARAM="${CERTREQ_CNLONG}"
fi
CERTREQ_SUBJECT="$( echo ${CERTREQ_SUBJECT} | sed -r -e "s/CERTREQ_CNPARAM/${CERTREQ_CNPARAM}/g;" )"
define_if_new CERTREQ_SUBJECT "/DC=com/DC=example/DC=ad/CN=${CERTREQ_CNSHORT}/CN=${CERTREQ_CNPARAM}"

# calculate the MSCA
if test -n "${CERTREQ_CAPARAM}";
then
   # trim down to just the hostname
   CERTREQ_CAPARAM="$( echo "${CERTREQ_CAPARAM}" | sed -r -e 's/https?:\/\///g' -e 's/(\.[a-z]{2,3})\/$/\1/;' )"
   CERTREQ_CA="http://${CERTREQ_CAPARAM}"
fi
define_if_new CERTREQ_CA "http://ca2.ad.example.com"
# generate cahost
CERTREQ_CAHOST="$( echo "${CERTREQ_CA}" | sed -r -e 's/https?:\/\///g' -e 's/(\.[a-z]{2,3})\/$/\1/;' )"

## REACT TO BEING A CRONJOB
#if test ${is_cronjob} -eq 1;
#then
#   [ ]
#else
#   [ ]
#fi

# SET TRAPS
#trap "CTRLC" 2
#trap "CTRLZ" 18
trap "clean_certreq" 0

# DEBUG SIMPLECONF
debuglev 5 && {
   ferror "Using values"
   # used values: EX_(OPT1|OPT2|VERBOSE)
   set | grep -iE "^CERTREQ_" | {
      if fistruthy "${NO_MASK}" ;
      then
         cat
      else
         sed -r -e 's/(CERTREQ_PASS=).*$/\1**********************/;'
      fi
   } 1>&2
}

# MAIN LOOP
{

   case "${CERTREQ_ACTION}" in
      list)
         action_list_templates "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
         ;;
      *)
         # default action
         action_get_cert "${CERTREQ_CNPARAM}" "${CERTREQ_SUBJECT}" "${CERTREQ_USER}:${CERTREQ_PASS}" "${CERTREQ_CA}" "${CERTREQ_CAHOST}"
         # CHECK EVERYTHING
         failed=0
         openssloutput="$( openssl x509 -in "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" -noout -subject -issuer -startdate -enddate 2>/dev/null )"
         grep -qE -- 'REQUEST--' "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" && failed=$(( failed + 1 ))
         grep -qiE '\<\/?body\>' "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" && failed=$(( failed + 2 ))
         test ${finaloutput} -ne 0 && failed=$(( failed + 4 ))
         grep -qE -- '--END CERTIFICATE--' "${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt" || failed=$(( failed + 8 ))
         #echo "${openssloutput}" | grep -qE "subject.*${CERTREQ_SUBJECT}" || failed=$(( failed + 16 ))
         echo "${openssloutput}" | grep -qE "issuer.*" || failed=$(( failed + 16 ))
         ;;
   esac

} 1> ${logfile} 2>&1

case "${CERTREQ_ACTION}" in
   list)
      # echo the variable from action_list_templates
      echo "${AVAILABLE_TEMPLATES}"
      ;;
   *)
      # for generate and generate-csr and everything else really

      # if everything was successful, display information below
      #if test ${failed} -eq 0;
      #then
         echo "workdir: ${CERTREQ_WORKDIR}"
         echo "logfile: ${logfile}"
         echo "certificate: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.crt"
         echo "key: ${CERTREQ_WORKDIR}/${CERTREQ_CNPARAM}.key"
         echo "chain: ${CERTREQ_WORKDIR}/${CHAIN_FILE}"
      #fi
      clean_certreq
      exit "${failed:-0}"
      ;;

esac

# EMAIL LOGFILE
#${sendsh} ${sendopts} "${server} ${scriptfile} out" ${logfile} ${interestedparties}
