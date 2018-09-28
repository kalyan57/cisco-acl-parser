# cisco-acl-parser

This parser would rewrite a huge unreadable cisco ACL (you can't understand which rule grants access to a certain user) into a few little user-specific ACLs.
Script is very narrow-specific and designed only for certain task - prepare readable little ACLs for VACL filtering mechanism.

## ALGORITHM:
* script reads ACL and collects its rules and source IPs of the rules
* list of source IPs then gets deduplicated - only unique IP addresses are left
* each IP address gets resolved into domain name: if there is no domain name - rule is outdated and won't be transfered in new configuration, it would be dropped
* having hostname script then looks for user name in reference file
* finally we select from collected rules of initial ACl only this user PC (hostname) rules by IP and rewrite them into a usernamed ACL
* actions from 3 to 5 are iterated for each IP address 

## [Rguirements:]

Note: install dependencies:
```
pip install pandas xlrd xlwt argparse
```

## [USAGE]
script takes two input files: 
* acl.txt
* reference.xls 
acl - any text file containing cisco acl configuration: may take it from config or as "sh ip access-list list" command output. 
Reference file - is an excel file, containing full usernames and associated list of computer names (hostname or FQDN) in certain (!) fields (field name matters)
### ARGUMENTS:
*	-h get help on script usage 
*	-i <acl.txt> - submit input acl. Default = acl.txt
*	-r <reference.xls> -submit reference excel file. Default = reference.xls
*	-p <acl_name_preffix> - preffix in new generated ACLs. For example: "video-" preffix would create video-ivanov, video-petrov, video-smith names for ne ACLs. Default is empty
*	-ot <out_text_filename> - submit name for output text file. Default = out.txt
*	-o <out_xls_filename> - submit name for output excel file. default = out.xls

## [OUTPUT]
* out.xls - all collected data: IP, domain name, Full user name, and generated user-specific ACL
* out.txt - all the same data in text format
	
