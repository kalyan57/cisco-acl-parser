# DEPENDENCIES: pandas, xlrd, xlwt (maybe openpyxl)
# Note: install dependencies:
# pip install pandas, xlrd, xlwt
# Python 3

# Only for host rules!!! subnets woun't pass, would be ignored 
import re
import socket
import pandas as pd
import argparse

################################==INIT-CONFIG==################################
desc = """
 acl-parser 
 
Script allows to rewrite large unreadable cisco ACL into a few named 
user-related 
"""
parser = argparse.ArgumentParser(description=desc)
parser.add_argument('-i', '--init_acl', dest='inacl', default='acl.txt',
					help='Submit filename of an ACL to process. (default = acl.txt)')
parser.add_argument('-r', '--reference', dest='ref', default='reference.xls',
					help='Submit reference excel file name. (default = reference.xls)')
parser.add_argument('-p', '--preffix', dest='apref', default='',
					help='Submit preffix for names of new ACLs. (default is empty)')
parser.add_argument('-ot', '--out_txt', dest='otxt', default='out.txt',
					help='Submit output txt file name. (default = out.txt)')
parser.add_argument('-o', '--out_excel', dest='oxls', default='out.xls',
					help='Submit output excel file name. (default = out.xlsx)')
args = parser.parse_args()

config = """
Current configuration:

Input ACL = %s
Reference file = %s
Preffix for new ACLs = %s
Output TEXT file = %s
Output EXCEL file = %s
"""
config %= (args.inacl, args.ref, args.apref, args.otxt, args.oxls)

################################==INIT-CONFIG==################################


# dictionary for russian-to-english transliteration of usernames
dict = {		
	'а':'a',
	'б':'b',
	'в':'v',
	'г':'g',
	'д':'d',
	'е':'e',
	'ё':'e',
	'ж':'zh',
	'з':'z',
	'и':'i',
	'й':'y',
	'к':'k',
	'л':'l',
	'м':'m',
	'н':'n',
	'о':'o',
	'п':'p',
	'р':'r',
	'с':'s',
	'т':'t',
	'у':'u',
	'ф':'f',
	'х':'h',
	'ц':'ts',
	'ч':'ch',
	'ш':'sh',
	'щ':'tsh',
	'ъ':'',
	'ы':'i',
	'ь':'',
	'э':'e',
	'ю':'yu',
	'я':'ya',	
	}

################################==FUNCTIONS==################################

def unique(lst):
    """
	Function leaves only unique values in provided list
	
	Args:
		lst (list): list containing nonunique elements
		
	Returns:
		list: list containing only unique elements
	"""
    # convert the list to the set (unique by design)
    list_set = set(lst)
    # convert unique set back to the list and return it
    return list(list_set)
   

def prep_df(cols):
	"""
	Function prepares empty Pandas DataFrame with submitted 
	column names
		
	Args:
		cols (list of strings): list of column names
		
	Returns: 
		Pandas DataFrame: prepared empty dataframe with provided column names
	"""
	return pd.DataFrame(columns = cols)


def wash_the_rule(rstr):
	"""
	Function removes index and counters from the rule text
	
	Args:
		rstr (str): string containing ACL rule text
	
	Returns:
		str: string of ACL rule without index and counters
	"""
	perm_pos = rstr.find('permit')
	if perm_pos!= -1: # it's a permit rule, ok - go on
		rstr = rstr[perm_pos:] # remove index before 'permit'
		
		parenthesis_pos = rstr.find('(')
		if parenthesis_pos != -1: # if parenthesis found
			return rstr[:parenthesis_pos] # then remove counter
		else:
			return rstr # leave string unchanged
			
	else:
		raise Exception('This script works only with PERMIT rules, DENY found!')

		
def get_target_ip(str):
	"""
	Function discerns target IP wich:
			- is not from vlan130
			- is not a subnet addresses
			- is not a wildcard mask
	Args:
		str (str): string of ACL rule
	
	Returns:
		str: target IP address or 'NA' in case of found IP doesn't meet requirements
	"""
	# getting list of all the ip addresses from ACL
	# !!!Attention!!! used here regexp is not ideal for decanting IPs
	#from strings, errors are possible
	# !!! This is the first place to improve, in fact								<<<=============
	# ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', str )# finds all matches of pattern
	ip = re.search( r'[0-9]+(?:\.[0-9]+){3}', str ).group()
	if any (sub in ip for sub in ['.0', '10.64.130']):
		return 'NA' # if found ip is inappropriate - return 'NA'
	else:
		return ip 
	
	
def decant(str):
	"""
	Function decants target host IP and the clear ACL rule (without 
	index in the beginning and counters in the end).
		
	Args:
		str (str): string of ACL rule
	
	Returns:
		str: target IP 
		str: ACL rule cleared from rule index and packet counters
	"""
	rule = wash_the_rule(str).strip()
	tip = get_target_ip(rule)
	return tip, rule
	
	
def read_acl(fname):
	"""
	Function reads out provided text file containing cisco ACL data,
	decants necessary data and returns it
	
	Args:
		fname (str): file name with text of cisco ACL
		
	Returns:
		Pandas DataFrame: contains target ip and clear ACL rule
		list: found list of IP addresses
	"""
	# column list for DataFrame for read data from ACL
	columnss = ['tip', 'rule']
	# prepare empty store for read data
	acldata = prep_df(columnss)
	ip_list = []
	with open(fname) as aclfile:
		for line in aclfile:
			if ('perm' in line or 'deny' in line): # work only with rules
				tip, rule = decant(line)
				if  tip == 'NA':
					pass
				else:# append only target entries, no entries with 'NA' target IP
					acldata = acldata.append({'tip':tip, 'rule':rule}, ignore_index = True)
					ip_list.append(tip)
			else: # lines other than rules are skipped
				pass
	
	# return data read from ACL file
	return acldata, ip_list


def resolve(ip):
	"""
	Function resolves IP address into FQDN, Returns only hostname
	
	Args:
		ip (str): IP address
	
	Returns:
		str: hostname
	"""
	try:
		name, aliaslist, ipaddr = socket.gethostbyaddr(ip)
	except Exception as e:
		return str(e)
	else:
		return name[:name.find('.')]

		
class infocollector(object):
	"""
	An object of infocollector class stores reference information from 
	provided file and allows to perform search of user name by hostname
	!May be used for search of any other kind of reference information from file
	"""
	
	def __init__(self, file):
		"""
		On init takes a file name of an excel file containing reference information
		and reads content of that file into an internal class Pandas DataFrame
		"""
		self.df = pd.read_excel(file)
		
	def get_user(self, hostname):
		"""
		Method takes hostname and searches for user of prvided PC
		
		Args:
			hostname (str): hostname
		
		Returns:
			str: Full name of user of the submitted PC
		"""
		#df[df['Номер КЕ'].str.contains(hostname), False)] # second param False will cause case insensitive search
		na_df = self.df.loc[self.df['Номер КЕ'].str.contains(hostname, False), 
						 ['ФИО контакта (П-КЕ)','Номер КЕ']] # leaves only related data
		res_df = na_df.dropna() # removes records with empty values
		if len(res_df.index) > 0: # if there is any name - return it
			return res_df.iloc[0]['ФИО контакта (П-КЕ)']
		else: # otherwise return hostname with attention comment
			return hostname + ' !!!Attention: username not found!'


def transl(word, d):
	"""
	Function transliterates submitted russian word into english in
	according to submitted dictionary
	
	Args:
		word (str): lowcase string in russian 
		d (dict): transliteration dictionary
	
	Returns:
		str: transliterated in english string
	"""
	out = ''
	for letter in word: # transliterate
		try:
			out += d[letter]
		except:
		# exception because there is no letter key in dictionary (submitted word
		# is in english - in case username hadn't been found and hostname submitted)
			out += letter
	return out	
		
def gen_acl(ip, user):
	"""
	Function generates new named ACL for submitted user and includes
	all rules (from stored data in inacl) related to submitted ip. 
	
	Args:
		ip (str): ip addres, is used to select only IP-related ACL rules
		user (str): full name of user, is used in name of new ACL
		
	Returns:
		str: text of a new named ACL for submitted user
	"""
	user = user[:user.find(' ')].lower() # get only first name and lower case
	acl_name = transl(user, dict) # transliterate russian in english
	df = inacl[inacl['tip'].str.contains(ip, False)] # collect rules only for submitted ip
	
	acl = 'ip access list ext %s%s \n' % (args.apref, acl_name)
	for index, row in df.iterrows(): # fill in new ACL with collected rules
		acl += '\t%s\n' % row['rule'] 
		
	print(acl)
	return acl
	
		
def elaborate(ips):
	"""
	Function collects all the necessary data for new ACL and generates it
	
	Args:
		ips (list): list of unique ip addresses from initial ACL

	Returns:
		pandas DataFrame: 	contains ip, hostname, username and new generated
							named ACL for user 
		srt:				text representation of collected data
	"""
	columns = ['ip', 'hname', 'user', 'acl']
	base = prep_df(columns) # prepare empty DataFrame for all data
	ref = infocollector(args.ref) # read reference file into infocollector class instance
	otxt = '' # init output text file content variable
	for ip in ips:
		#hname, user, = collect_info(ip) # collect necessary data
		hname = resolve(ip) # get hostname by IP 
		if 'host not found' in hname: # if hostname can't be resolved
			pass # then rule is outdated, do nothing
		else: # otherwise continue
			print('working with ip: %s, hostname: %s' % (ip, hname))
			user = ref.get_user(hname) # get user name by hostname
			print (user)
			acl = gen_acl(ip, user) # generate new ACL for a user
			base = base.append({'ip' : ip,  # write record of all collected and generated data
							'hname' : hname,
							'user' : user,
							'acl' : acl 
							}, ignore_index = True)
			otxt += '%s: %s: %s \nacl: \n%s \n\n' % (user, hname, ip, acl)
	return base, otxt
	
	
def save(base, txt):
	"""
	Function saves collected data to text and excel files 
	
	Args:
		base (pandas DataFrame): DF containing all collected data which would be saved to excel file
		txt (str): text representation of thr same data, would be saved to text file
		
	Returns:
		str: result of save operation
	"""
	out_txt = args.otxt
	out_xls = args.oxls
	err = '' # init error collector
	succ = '' # init succsess message collector
	try:
		with open(out_txt, 'w') as file: # try to write text output 
			txt = 'Script was run with following config: \n %s \n\n%s' % (config, txt)
			file.write(txt)
			succ += 'Text file %s is saved successfully! \n' % out_txt
	except Exception as e:
		err += 'Error saving text file %s: %s \n' % (out_txt, str(e))
	
	try: # try to write Excel output 
		writer = pd.ExcelWriter(out_xls)
		new_base.to_excel(writer)
		writer.save()
		succ += 'Excel file %s is saved successfully! \n' % out_xls
	except Exception as e:
		err += 'Error saving Excel file %s: %s \n' % (out_xls, str(e))		
	
	return '%s ERRORS: %s\n' % (succ, err)
	
################################==FUNCTIONS==################################	


###############################---BODY=HERE---#######################################

# print out current config		
print (config)

inacl, ips = read_acl(args.inacl) # read initial ACL into dataframe and get list of target IPs
print ("Rules in submitted ACL:")	# print out what we've got
with pd.option_context('display.max_rows', None, 'display.max_columns', 3):
	print(inacl)

ips = unique(ips) # deduplicate list of IPs and print them out
print ('List of unique IPs: \n', '\n'.join(ips), '\nAmount of unique IPs: ', len(ips))

# elaborate on unique list: collect and generate all necessary data to rewrite 
# initial unreadable ACL into a collection of named user-related ACLs
new_base, txt = elaborate(ips) 
print('All collected data so far: \n') # print out what we've got so far
with pd.option_context('display.max_rows', None, 'display.max_columns', 3):
    print(new_base) 

	
fin = save(new_base, txt)# save all the data
print(fin) # and print out results	

###############################---BODY=HERE---#######################################