#!/usr/bin/python
import pefile
import macholib.MachO
import sys
import re
import magic 
from math import log, e
import pylzmat
import lzma
import os
from scipy.stats import entropy
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from _pylzmat import lib, ffi

def file_size(file_path):

    if os.path.isfile(file_path):
		file_info = os.stat(file_path)
		return file_info.st_size

def find_packer(name,entropy):
	
	if entropy > 6.8:
 		print "Executabilul  cel mai probabil a fost pack-uit... se incearca identificarea packer-ului...\n"
	
    		if re.search("UPX",name):
    			print "Packerul folosit este:UPX"
    		elif re.search("MPRESS",name):
    			print "Packerul folosit este:MPRESS"
    		else:
    			print "Packerul nu a putut fi identificat..."
		return
    	else:
    		print "Sectiune Curata..."


def get_pe(file_path):


 pe = pefile.PE(file_path)

 
 
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
    		


def entropy1(labels, base=None):
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
 f.close(); 
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
        sectionEntropy = entropy1(get_bytes_section(file_path,sectionOffset,sectionSize))
        print "Sectiunea %s incepe de la offsetul %x si are o marime de %d ,fiind mapata la adresa virtuala %x cu protectiile %s , avand o entropie de %f. " % (sectionName, sectionOffset, sectionSize, sectionAddr,''.join(l), sectionEntropy)
        find_packer(sectionName,sectionEntropy)
        
        


def check_file(filename):
        try:
            # Parse the ELF header
            f = open(filename, 'rb')
            elffile = ELFFile(f)
           
            arch = elffile.header.e_machine.split('_')[1]
            
            for segment in elffile.iter_segments():
		print segment['p_type']

            for section in elffile.iter_sections():
                  l = ['-','-','-']
                  print "Ceva"
                  if section.header['sh_flags'] & 0x04:
                    l[2] = 'X'
                  if section.header['sh_flags'] & 0x01:
                    l[1] = 'W'
                  if section.header['sh_flags'] & 0x02:
                    l[0] = 'R'
                  sectionEntropy = entropy1(get_bytes_section(filename,section.header['sh_offset'],section.header['sh_size']))
                  print "Sectiunea %s incepe la offsetul 0x%x si are o marime de %d octeti si flagurile %s si o entropie de %f" % (section.name,section.header['sh_offset'],section.header['sh_size'],"".join(l),sectionEntropy)
                  find_packer(section.name,sectionEntropy)
	   
            


        except IOError:
            print("ERROR: Could not load the file '" + filename + "'.")
            exit(1)
        except ELFError:
            print("ERROR: '" + filename + "' is not a valid ELF object")
            exit(1)

def files_entropy(file_path):
 size1 = file_size(file_path)
 pk = get_bytes_section(file_path, 0, size1)
 return entropy(pk,None,2)
      
def KL_divergence(file_clean,file_suspicious):
 size1 = file_size(file_clean)
 size2 = file_size(file_suspicious)
 pk = get_bytes_section(file_clean, 0, size1)
 qk = get_bytes_section(file_suspicious, 0, size2)
 return entropy(pk,qk,2)


def RA_divergence(file_clean,file_suspicious):
 size1 = file_size(file_clean)
 size2 = file_size(file_suspicious)
 pk = get_bytes_section(file_clean, 0, size1)
 qk = get_bytes_section(file_suspicious, 0, size2)
 return 1/((1/entropy(pk,qk,2)) + (1/entropy(qk,pk,2)))


if __name__ == "__main__":
	m = magic.Magic()
	file_type = m.id_filename(sys.argv[1])
	if len(sys.argv) == 2:
	 magic.Magic.close(m)
	 if re.search("PE",file_type) or re.search("MZ",file_type):
	  get_pe(sys.argv[1])
	 if re.search("Mach-O",file_type):
	  get_Macho(sys.argv[1])
	 if re.search("ELF",file_type):
	  check_file(sys.argv[1])
	  find_packer(sys.argv[1],files_entropy(sys.argv[1]))
	if len(sys.argv) == 4:
	 if sys.argv[1] == 'PE':
	  file_types1 = m.id_filename(sys.argv[2])
	  file_types2 = m.id_filename(sys.argv[3])
	  if re.search("PE",file_types1) and re.search("PE",file_types2):
	    print "KL divergence este :%lf " % (KL_divergence(sys.argv[2],sys.argv[3]))
	  else:
	    print "Formate Incorecte!"
	 if sys.argv[1] == 'ELF':
	  file_types1 = m.id_filename(sys.argv[2])
	  file_types2 = m.id_filename(sys.argv[3])
	  if re.search("ELF",file_types1) and re.search("ELF",file_types2):
	   print "RA divergence este : %lf " % (RA_divergence(sys.argv[2],sys.argv[3]))
	  else:
	   print "Formate Incorecte!"
	magic.Magic.close(m)
	
	

