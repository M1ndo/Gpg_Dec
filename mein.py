#!/usr/bin/env python3
import os,datetime,optparse,fnmatch,shutil
import lib.gnupg as gnupg,sqlite3 as sql
from terminaltables import AsciiTable

# General
gpg = gnupg.GPG(verbose=False)
gpg.encoding = 'utf-8'
HOME = os.environ.get("HOME")
conn = sql.connect('%s/.gnupg/keys.db'%(HOME))
cur = conn.cursor()
date = datetime.datetime.now()
com_date = "%s/%s/%s %s:%s:%s"%(date.year,date.month,date.day,date.hour,date.minute,date.second)
answers = [ "y","Y","yes","YES"]
key_list = [];root_f = []

def add_to_table(mail,keyid,finger):
    """ Add GPG Value To Database"""
    cur.execute("select * from keys where keyid = '%s'" %(keyid))
    rows = cur.fetchall()
    if bool(rows) == 0:
        p = 0
    else:
        if not quiet: print("[!] KeyId %s Is Already In Database Skipping"%(keyid)); p = 1
        else: p = 1
    if p == 0:
        try:
            cur.execute("insert into keys values (?,?,?,?)",(mail,keyid,finger,com_date))
            conn.commit()
        except Exception as e:
            print("Error Happened")
            print(e)
            exit(1)
    return

def add_df(key):
   """ Add Specified Key As a Default Key For Encrypting/Decrypting/Signing"""
   cur.execute("select id,def from default_key where id = '1'")
   rows = cur.fetchall()
   if bool(rows) == 0:
       pass
   else:
       print("[!] KeyId %s Is Already Set As The Default Key"%(rows[0][1]))
       ch = input("[!] Overwrite The Current Key?: ")
       if ch in answers:
           cur.execute("delete from default_key where def = '%s'"%(rows[0][1]))
           conn.commit()
           pass
       else:
           return False
   try:
       cur.execute("insert into default_key values (?,?,?)",("1",key,com_date))
       conn.commit()
   except Exception as e:
       print("Error Happened")
       print(e)
       exit(1)
   return True



def sqlite_gen():
    """ Generate tables if they don't exists """
    try:
        cur.execute("""CREATE TABLE keys
            (mail text,keyid text,finger text,date text)""")
    except sql.OperationalError:
       pass
    try:
        cur.execute("""CREATE TABLE default_key
            (id text, def text, date text)""")
    except Exception:
        pass

def fetch_db():
    """ Fetch Keys From database """
    try:
        cur.execute("select def from default_key")
        row = cur.fetchall()
        if bool(row) != 0:
            def_key = row[0][0]
        else:
            def_key = ""
    except Exception as e:
        print (e)
        exit(1)

    try:
        cur.execute("select mail,keyid,date,finger from keys")
        rows = cur.fetchall()
    except Exception as e:
        print(e)
        pass

    return rows,def_key

def list_dir(dire):
    """ Recursively Look For Encrypted Files"""
    files = []
    for r,d,f in os.walk(dire):
        for file in f:
            files.append(os.path.join(r,file))
    return files

def cr_en(dir_root):
    if dir_root.endswith("/"): dir_root=dir_root[:-1]
    else: pass
    enc_dir = dir_root+"_encrypted/"
    if os.path.isdir(enc_dir): pass
    else: os.mkdir(enc_dir)
    return enc_dir

def return_file(file):
    """ Check if file is a file or a folder if is a folder then return a file """
    if os.path.isfile(file):
        return file
    elif os.path.isdir(file):
        root_f.append(cr_en(file))
        file = list_dir(file)
    else:
        print("[!] No Such Directory Nor File Exists");exit(1)
    return file

def enc(file,recp,c,d):
    """
    This function encrypts file/folder
    As it is done with the encryption it will automatically shred those encrypted
    files (optional)
    """
    gpg = gnupg.GPG(default_key=d,verbose=False)
    try:
        if type(file) == list:
            for f in file:
                stream = open(f,'rb')
                dirs = os.path.dirname(f)
                dir = root_f[0]+"/".join(dirs.strip("/").split("/")[1:])
                if os.path.isdir(dir): pass
                else: os.mkdir(dir)
                enc = gpg.encrypt_file(stream,recp,armor=False,sign=True,always_trust=True,output=dir+"/"+os.path.basename(f)+".gpg")
                if "invalid recipient" in enc.status:
                    print("[!] invalid recipient")
                    exit(1)
                signme = sign(dir+"/"+os.path.basename(f)+".gpg",d)
        else:
            stream = open(file,'rb')
            enc = gpg.encrypt_file(stream,recp,armor=False,sign=True,always_trust=True,output=file+".gpg")
            if "invalid recipient" in enc.status:
                print("[!] invalid recipient")
                exit(1)
            signme = sign(file+".gpg",d)
        if root_f:
            if os.path.isfile(root_f[0][:-1]+".tar.bz2"): pass
            else:
                if c: r = compress(root_f[0]);print("[+] Compressed Directory: %s"%(r))
    except Exception as e:
        print("[!] Error Happened, Encrypting files");print(e);exit(1)
    return enc,signme

def dec(file):
    """
    This function decrypt file/folder
    """
    gpg = gnupg.GPG(verbose=False)
    try:
        if type(file) == list:
            for f in file:
                stream = open(f,'rb')
                dirs = os.path.dirname(f)
                dir = root_f[0].replace("_encrypted","")+"/".join(dirs.strip("/").split("/")[1:])
                if not dir.endswith('/'): dir = dir+"/"
                else: pass
                if os.path.isdir(dir): pass
                else: os.mkdir(dir)
                if "sig" in f:
                    verify = check_sign(f)
                    f = f.replace('.sig','')
                    print(verify.status + " File: %s"%(f))
                dec = gpg.decrypt_file(stream,always_trust=True,output=dir+os.path.basename(f).replace(".gpg",''))
                dec.status = "decryption ok"
            os.rmdir(root_f[0]);shutil.rmtree(root_f[0].replace('_encrypted/',''))
        else:
            stream = open(file,'rb')
            dec = gpg.decrypt_file(stream,always_trust=True,output=file.replace(".gpg",''))
    except Exception as e:
        print("[!] Error Happened, Decryptig files");print(e);exit(1)
    return dec

def sign(file,key):
    """
    This function signs a file
    """
    try:
        stream = open(file,'rb')
        sign = gpg.sign_file(stream,keyid=key,clearsign=False,binary=True,detach=True,output=file+".sig")
    except Exception as e:
        print("[!] Error Happened, Signing a file");print(e);exit(1)
    return sign

def check_sign(file):
    """
    This function check a files signature
    """
    try:
        stream = open(file,'rb')
        verify = gpg.verify_file(stream,file.replace('.sig',''))
    except Exception as e:
        print("[!] Error Happened, Checking Signature");print(e);exit(1)
    return verify

def gen():
    """
    This function generates a key
    """
    data_inp = input("[+] Enter (Username,Email,Password): ")
    name,mail,passw = data_inp.split(",")
    parms = gpg.gen_key_input(
        name_email=mail,name_real=name,passphrase=passw,
        expire_date="365d",key_type="RSA",key_length="2048")
    key = gpg.gen_key(parms)
    keyid = key.gpg.list_keys(True)[len(key.gpg.list_keys(True)) - 1]['keyid']
    return True,keyid

def imp_k(key):
    """
    This function imports a key
    """
    return

def ls_private_k():
    """
    Return list of private keys
    """
    private_keys = gpg.list_keys(True)
    c = len(private_keys)
    db = []
    keys = []
    fings = []
    if bool(c) == 0:
        return 0,0,0
    else:
        for i in range(0,c):
            k = private_keys[i]
            keyid,fingerprint,mail = k['keyid'],k['fingerprint'],k['uids']
            db.extend([''.join(map(str,mail))])
            keys.extend([keyid])
            fings.extend([fingerprint])
    return db,keys,fings

def argums():
    """
    List of available arguments
    """
    usage =  "Usage: mein [options] file"
    desc = "Mein is a fully fast and easy wrapper around gpg"
    vers = "v1.0"
    opt = optparse.OptionParser(usage=usage,version=vers,description=desc)
    opt.add_option('-f', '--file',dest='file',type='string',help='File/Folder To Encrypt/Decrypt')
    opt.add_option('-k','--key',dest='key',type='string',help="Key To Encrypt/Decrypt With (Optional)")
    opt.add_option('-r','--recv',dest='recv',type='string',help="Receiver Mail To Encrypt Data To")
    opt.add_option('-c','--compress',dest='comp',action="store_true",default=False,help="Compress Encrypted Data (Default False)")
    opt.add_option('-g','--generate',dest='gen',action="store_true",default=False,help="Generate A New Key (RSA 2048 (1year))")
    opt.add_option('-l','--list',dest='listme',action="store_true",default=False,help="List All Available Keys!")
    opt.add_option('-d','--default',dest='defa',type='string',help="Set (Permenant) Default Key To Use For Enc/Dec")
    opt.add_option('-v','--verbose',dest='verb',action="store_true",default=False,help="Disable Quiet Output (Default False)")
    (options,args) = opt.parse_args()
    return options,args

def gen_k():
    gene,keyid = gen()
    if gene:
        print("[+] Key Genereted With KeyId %s" %(keyid))
        sc = input("[+] Set Key As Default Key?: ")
        if sc in answers:
            if add_df(keyid):
                print("[+] Key Added Successfully")
            else:
                print("[!] Could No Add Key (Permission Denied)")

def ch_del_df(key):
    """ Delete key (removed) set as a default """
    cur.execute("select def from default_key where def = '%s'"%(key))
    r = cur.fetchall()
    if bool(r) == 0:
        pass
    else:
        print("[!] KeyId %s Was Set As Default Key, Removing .."%(key))
        cur.execute("delete from default_key where def = '%s'"%(key))
        conn.commit()


def ch_del_keys(db_keys):
    """ Checks if a keys has been delete then updates db """
    for t in db_keys:
        if t[1] in key_list:
            pass
        else:
            print("[!] Key %s Doesn't Exists, Removing ..."%(t[1]))
            cur.execute("delete from keys where keyid = '%s'"%(t[1]))
            conn.commit()
            ch_del_df(t[1])


def check_me(file):
    if type(file) == list:
        if "gpg" in file[0]: return True
        else: return False
    else:
        if "gpg" in file: return True
        else: return False

def check_comp(file):
    """ Check if file is compressed """
    if ".tar" in file:
        f = decompress(file); return f
    else: return file

def compress(file):
    """ This function compresses a folder, It only works on folders because who wants to
        compress a file ???
        PS: I'll add a file compression later :)
    """
    try:
        # basename=os.path.dirname(file[0])
        r = shutil.make_archive(file,"bztar",file)
        return r
    except Exception as e:
        print(e)

def decompress(file):
    """ This function decompresses an archive then returns decompressed files """
    basename=os.path.basename(file)
    out_base = basename.replace('.tar.bz2','')
    shutil.unpack_archive(basename,out_base,"bztar")
    return out_base


def main():
    """
    Main function
    """
    global quiet
    sqlite_gen()
    options,args = argums()
    file = options.file
    key = options.key
    recv = options.recv
    comp = options.comp
    if options.verb: quiet=False
    else: quiet=True

    if options.gen:
        gen_k()

    defa = options.defa
    if defa != None:
        if add_df(defa):
            print("[+] Key Added Successfully")
        else:
            print("[!] Could No Add Key (Permission Denied)")

    e,k,f = ls_private_k()
    if e == 0:
        print( "[!] NOT PRIVATE KEYS FOUND!" )
        ans = input( "[+] Generate New Key?: " )
        if ans in answers:
            gen_k()
        else:
            print( "[!] With No Key, There's Nothing To Do \n[!] Quiting ..." )

    for i in range(0,len(e)):
        if quiet: pass
        else: print("[+] Found Key %s Owned By %s"%(k[i],e[i])); print("[+] Adding To Database Key %s" %(k[i]))
        key_list.append(k[i])
        add_to_table(e[i],k[i],f[i])

    rows,default = fetch_db()
    ch_del_keys(rows)
    if options.listme:
        if bool(rows) != 0:
            table_data = [["Name/Mail","KeyId","Fingerprint","Date"]]
            for i in range(0,len(rows)):
                if default == rows[i][1]: n_m=rows[i][0]+" (d)"
                else: n_m=rows[i][0]
                table_data.extend([[n_m,rows[i][1],rows[i][3],rows[i][2]]])
            table = AsciiTable(table_data,title="Available Keys")
            print(table.table)
            exit(0)

    if file == None:
        try:
            file = args[0]
        except: print("[!] No file || recipent specified, Quitting ..");exit(1)
    if default == '': default = None
    elif key != None: default = key
    else: pass
    file = check_comp(file)
    if check_me(return_file(file)):
        s = dec(return_file(file))
        print("%s"%(s.status))
    else:
        try:
            if recv != None: recp = recv
            else: recp = args[1]
            if "," in recp: recp = recp.split(',')
            else: pass
            s,me = enc(return_file(file),recp,comp,default)
            print("%s"%(s.status))
            print("%s"%(me.status))
        except Exception as e:
            print("Attempting To Encrypt a file without a recipent ???")
            print(e)

main()
