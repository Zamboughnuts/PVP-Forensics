from __future__ import print_function
import argparse
import os
import pytsk3
import pyewf
import sys
import csv
import hashlib
from tqdm import tqdm
from tabulate import tabulate

__description__ = "Plain View Privacy script"
__authors__ = "Steve Noble"
__date__ = "June 11, 2019"


"""

ORIGINAL COPYRIGHT NOTICE:

MIT License

Copyright (c) 2017 Chapin Bryce, Preston Miller

Please share comments and questions at:
    https://github.com/PythonForensics/PythonForensicsCookbook
        or email pyforcookbook@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""




def main(image, img_type, offset, hashListFile, evidence_Dir, part_Type, pbar_total=0):
	matched_Hash_Files = {}
	hash_List, type_of_Hash = get_Hash_Type(hashListFile)
	volume = None
	print("[+] Opening {}".format(image))
	if img_type == "ewf":
		try:
			filenames = pyewf.glob(image)
		except IOError:
			_, e, _ = sys.exc_info()
			print("[-] Invalid EWF format:\n {}".format(e))
			sys.exit(2)
		ewf_handle = pyewf.handle()
		ewf_handle.open(filenames)
	# Open PYTSK3 handle on EWF Image
		img_info = EWFImgInfo(ewf_handle)
	else:
		img_info = pytsk3.Img_Info(image)

	# The above code is taken from the "Combining pyewf with pytsk3" section of
	# the python development page for pyewf

	try:
		if part_Type is not None:
			attr_ID = getattr(pytsk3, "TSK_VS_TYPE_" + part_Type)
			volume = pytsk3.Volume_Info(img_info, attr_ID)
		else:
			volume = pytsk3.Volume_Info(img_info)
	except IOError:
		_, e, _ = sys.exc_info()
		print("[-] Unable to read partition table:\n {}".format(e))
		exit()

	finished_fileDict = open_FS(volume, img_info, hash_List, type_of_Hash, matched_Hash_Files, evidence_Dir, pbar_total)

	for hash_Value in hash_List:
		if hash_Value in finished_fileDict:
			print("value for %r in finished_fileDict: %r" % (hash_Value, finished_fileDict[hash_Value]))
		else:
			continue

	finished_evidenceDict = os_Hash_Check(evidence_Dir, hash_List, type_of_Hash)
	
	for hash_Value in hash_List:
		if hash_Value in finished_fileDict:
			print("value for %r in finished_evidenceDict: %r" % (hash_Value, finished_evidenceDict[hash_Value]))
		else:
			continue
	

def get_Hash_Type(hashes):
	hash_List_To_Match = []
	hash_Type = None
	with open(hashes) as infile:
		for line in infile:
			if hash_Type is None:
				if len(line.strip()) == 32:
					hash_Type = "md5"
				elif len(line.strip()) == 40:
					hash_Type = "sha1"
				elif len(line.strip()) == 64:
					hash_Type = "sha256"
			hash_List_To_Match.append(line.strip().lower())
	if hash_Type is None:
		print("[-] No valid hashes identified in {}".format(hashes))
		sys.exit(3)
	return hash_List_To_Match, hash_Type


def open_FS(vol, img, hashes, hash_Type, fileDict, output_Dir, pbar_total=0):
	print("[+] Recursing through and hashing files")
	pbar = tqdm(desc="Hashing", unit=" files", unit_scale=True, total=pbar_total)
	if vol is not None:
		for part in vol:
			if part.len > 2048 and "Unallocated" not in part.desc and \
			"Extended" not in part.desc and "Primary Table" not in part.desc:
				try:
					fs = pytsk3.FS_Info(img, offset=part.start * vol.info.block_size)
				except IOError:
					_,e,_ = sys.exc_info()
					print("[-] Unable to open FS:\n {}".format(e))
				root = fs.open_dir(path="/")
				current_FileDict = recurse_Files(part.addr, fs, root, [], [""], hashes, hash_Type, pbar, output_Dir, fileDict)
	else:
		try:
			fs = pytsk3.FS_Info(img)
		except IOError:
			_,e,_ = sys.exc_info()
			print("[-] Unable to open FS:\n {}".format(e))
		root = fs.open_dir(path="/")
		current_FileDict = recurse_Files(1, fs, root, [], [""], hashes, hash_Type, pbar, output_Dir, fileDict)
	pbar.close()
	return current_FileDict


def recurse_Files(part, fs, root_Dir, dirs, parent, hashes, hash_Type, pbar, output_Dir, fileDict):
	dirs.append(root_Dir.info.fs_file.meta.addr)
	current_fileDict = fileDict
	for fs_object in root_Dir:
		if not hasattr(fs_object, "info") or not hasattr(fs_object.info, "name") or \
		fs_object.info.name.name in  [".",".."]:
			continue
		try:
			file_Path = "{}/{}".format("/".join(parent), fs_object.info.name.name)
			if getattr(fs_object.info.meta, "type", None) == pytsk3.TSK_FS_META_TYPE_DIR:
				parent.append(fs_object.info.name.name)
				sub_Dir = fs_object.as_directory()
				inode = fs_object.info.meta.addr
				if inode not in dirs:
					recurse_Files(part, fs, sub_Dir, dirs, parent, hashes, hash_Type, pbar, output_Dir, fileDict)
					parent.pop(-1)
			else:
				current_fileDict = hash_File(fs_object, file_Path, hashes, hash_Type, pbar, output_Dir, fileDict)
		except IOError:
			pass
	dirs.pop(-1)
	return current_fileDict

def hash_File(fs_object, path, hashes, hash_Type, pbar, output_Dir, fileDict):
	updated_fileDict = fileDict
	if hash_Type == "md5":
		hash_Obj = hashlib.md5()
	elif hash_Type == "sha1":
		hash_Obj = hashlib.sha1()
	elif hash_Type == "sha256":
		hash_Obj = hashlib.sha256()

	f_size = getattr(fs_object.info.meta, "size", 0)
	pbar.set_postfix(File_Size="{:.2f}MB".format(f_size / 1024.0 / 1024))
	hash_Obj.update(fs_object.read_random(0, f_size))
	hash_Digest = hash_Obj.hexdigest()
	#print("\n"+hash_Digest)
	pbar.update()

	if hash_Digest in hashes:
		file_Name = fs_object.info.name.name
		print(file_Name)
		pbar.write("\n[*] MATCH: {}\n{}".format(path, hash_Digest))
		updated_fileDict.update({hash_Digest : path})
		extract_Hash(fs_object, path, file_Name, output_Dir )
	return updated_fileDict

def extract_Hash(fs_Object, path, name, output_Dir):
	print("writing %r to evidence file" % path)
	evidence_Dir = os.path.join(output_Dir, os.path.dirname(path.lstrip("//")))
	if not os.path.exists(evidence_Dir):
		os.makedirs(evidence_Dir)
	with open(os.path.join(evidence_Dir, name), "w") as outputFile:
		outputFile.write(fs_Object.read_random(0,fs_Object.info.meta.size))

def os_Hash_Check(evidence_Dir, hash_List, hash_Type):
	evidenceDict = {}


	buf_Size = 4096
	for root, dirs, files in os.walk(evidence_Dir):
		for file_Name in files:
			path_File_Name = os.path.join(root,file_Name)
			with open(path_File_Name, 'rb') as f:
				data = f.read(buf_Size)
				if hash_Type == "md5":
					hash_Obj = hashlib.md5(data)
				elif hash_Type == "sha1":
					hash_Obj = hashlib.sha1(data)
				elif hash_Type == "sha256":
					hash_Obj = hashlib.sha256(data)				
				while data:
					data = f.read(buf_Size)
					hash_Obj.update(data)
						
				hash_Digest = hash_Obj.hexdigest()
				evidenceDict.update({hash_Digest : path_File_Name})
	return evidenceDict



class EWFImgInfo(pytsk3.Img_Info):
	def __init__(self,ewf_handle):
		self._ewf_handle = ewf_handle
		super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

	def close(self):
		self._ewf_handle,close()

	def read(self, offset, size):
		self._ewf_handle.seek(offset)
		return self._ewf_handle.read(size)

	def get_size(self):
		return self._ewf_handle.get_media_size()


if __name__=='__main__':
	parser = argparse.ArgumentParser(
		description=__description__,
		epilog="Developed by {} on {}".format(
			",".join(__authors__),__date__)
		)
	parser.add_argument("EVIDENCE_FILE",help="Evidence file path")
	parser.add_argument("TYPE",help="Type of evidence: raw(dd) or EWF (E01)", choices=("raw","ewf"))
	parser.add_argument("-o","--offset",help="Partition byte offset",type=int)
	parser.add_argument("HASH_LIST",help="File path to Newline-delimited list of hashes, (Either MD4, SHA1, or SHA-256)")
	parser.add_argument("-p", help="Partition Type", choices=("DOS","GPT","MAC","SUN"))
	parser.add_argument("-t", type=int, help="total number of files, for the progress bar")
	parser.add_argument("OUTPUT_DIR", help="output directory for extracted evidence")
	args = parser.parse_args()

	if os.path.exists(args.EVIDENCE_FILE) and os.path.isfile(args.EVIDENCE_FILE) and \
		os.path.exists(args.HASH_LIST) and os.path.isfile(args.HASH_LIST):
		main(args.EVIDENCE_FILE, args.TYPE, args.offset, args.HASH_LIST, args.OUTPUT_DIR, args.p, args.t) 
	else:
		print("[-] Supplied input file {} does not exist is or not a " "file".format(args.EVIDENCE_FILE))
		sys.exit(1)
