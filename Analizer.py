#!/usr/bin/python
import pefile
import macholib.MachO
import sys
import re
import magic 
from math import log, e







def find_packer(name,entropy):
	
	if entropy > 6.8:
 		print "Sectiunea  cel mai probabil a fost pack-uita... se incearca identificarea packer-ului...\n"
	
    		if re.search("UPX",name):
    			print "Packerul folosit este:UPX"
    		elif re.search("MPRESS",name):
    			print "Packerul folosit este:MPRESS"
    		else:
    			print "Packerul nu a putut fi identificat..."
    	else:
    		print "Sectiune Curata..."


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
 	
 	if characteristics & 0x20000000:
 		l[2] = 'X'
 	if characteristics & 0x40000000:
 		l[0] = 'R'
 	if characteristics & 0x80000000:
 		l[1] = 'W'


   	print "".join(l) + " " + section.Name.decode('utf-8') + "\tVirtual Address: " + str(hex(section.VirtualAddress)) + "\tVirtual Size: " + hex(section.Misc_VirtualSize) + "\tRaw Size: "+ hex(section.SizeOfRawData)  + " Entropy:" + str(section.get_entropy())
   	find_packer(section.Name.decode('utf-8'),entropy)

   	
 print "Executabilul importa urmatoarele DLL-uri:"

 for entry in pe.DIRECTORY_ENTRY_IMPORT:
    	print  entry.dll.decode('utf-8') + " De unde importa functiile:"
    	for func in entry.imports:
    		print "\t" + func.name.decode('utf-8') + " la adresa "+ hex(func.address)
    		


def entropy(labels, base=None):
  if labels == None:
   return 0 
  ent = 0
  for i in range(len(labels)):
	if labels[i] != 0:
		ent -= (labels[i] * log(labels[i],2))

  return ent

def get_bytes_section(file_path, offset, longer):
 if longer == 0:
  return None
 f = open(file_path,"rb")
 f.seek(offset,0)
 buf = f.read(longer)
 st = []
 for i in range(256):
  st.append(0)
 for i in range(len(buf)):
  st[ord(buf[i])] = st[ord(buf[i])] + 1
 for i in range(256):
   st[i] = float(st[i]) / float(longer)  
 return st




def get_Macho(file_path):

 Mach = macholib.MachO.MachO(file_path)
 for (load_cmd, cmd, data) in Mach.headers[0].commands:
    if hasattr(cmd, "segname"):
        l = ['-','-','-']
        if cmd.initprot & 0x04:
         l[2] = 'X'
        if cmd.initprot & 0x02:
         l[1] = 'W'
        if cmd.initprot & 0x01:
         l[0] = 'R'
        sectionName = getattr(cmd, 'segname', '').rstrip('\0')
        sectionOffset = cmd.fileoff
        sectionSize = cmd.filesize
        sectionAddr = cmd.vmaddr
        sectionEntropy = entropy(get_bytes_section(file_path,sectionOffset,sectionSize))
        print "Sectiunea %s incepe de la offsetul %x si are o marime de %d ,fiind mapata la adresa virtuala %x cu protectiile %s , avand o entropie de %f. " % (sectionName, sectionOffset, sectionSize, sectionAddr,''.join(l), sectionEntropy)
        find_packer(sectionName,sectionEntropy)

	


if __name__ == "__main__":
	m = magic.Magic()
	file_type = m.id_filename(sys.argv[1])
	if re.search("PE",file_type) or re.search("MZ",file_type):
		get_pe(sys.argv[1])
	if re.search("Mach-O",file_type):
		get_Macho(sys.argv[1])
	magic.Magic.close(m)
	

