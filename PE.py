#!/usr/bin/python
import pefile
import sys
import re

check = 0

def find_packer(name,entropy):
	#print entropy
	global check
	if entropy > 7.1 and check == 0:
 		print "PE-ul cel mai probabil a fost pack-uit... se incearca identificarea packer-ului...\n"
		check = 1
    		if re.search("UPX",name):
    			print "Packerul folosit este:UPX"
    		elif re.search("MPRESS",name):
    			print "Packerul folosit este:MPRESS"
    		else:
    			print "Packerul nu a putut fi identificat..."
    	else:
    		print "Binar Curat..."


def get_pe(file_path):


 pe = pefile.PE(file_path)

 #for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
   # print '\t' + data_directory.name
 #print pe.dump_info()
 #for i in pe.DIRECTORY_ENTRY_BASERELOC:
 	#print i
 
 print "Entry Point:" + str(hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
 print "\nSections:"
 for section in pe.sections:
 	l = ['-','-','-']
 	characteristics = getattr(section, 'Characteristics')
 	entropy = section.get_entropy()
 	find_packer(section.Name.decode('utf-8'),entropy)
 	if characteristics & 0x20000000:
 		l[2] = 'X'
 	if characteristics & 0x40000000:
 		l[0] = 'R'
 	if characteristics & 0x80000000:
 		l[1] = 'W'


   	print "".join(l) + " " + section.Name.decode('utf-8') + "\tVirtual Address: " + str(hex(section.VirtualAddress)) + "\tVirtual Size: " + hex(section.Misc_VirtualSize) + "\tRaw Size: "+ hex(section.SizeOfRawData)  + " Entropy:" + str(section.get_entropy())
   	

   	
 print "Executabilul importa urmatoarele DLL-uri:"

 for entry in pe.DIRECTORY_ENTRY_IMPORT:
    	print  entry.dll.decode('utf-8') + " De unde importa functiile:"
    	for func in entry.imports:
    		print "\t" + func.name.decode('utf-8') + " la adresa "+ hex(func.address)
    		





get_pe(sys.argv[1])
	

