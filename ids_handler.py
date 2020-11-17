#! /usr/bin/python
# -*- coding:utf-8 -*-

"""
# @author: lightk
# @date:2018/04/08
# @filename:ids_handler.py
"""

import os,re,sys
# from collections import defaultdict
from rule_model import IDS_RULE

def get_rules(path):
    filepath = {}
    for f in os.listdir(path):
        rupath = os.path.join(path, f)
        if os.path.isfile(rupath) and f.endswith(".rules"):
            yield rupath
            # key = "rule"+str(index)
    # return rule

    
def mk_new_dir(path):
    npath = os.path.abspath(path)
    try:
        new_path = npath + "_" + pri
        if os.path.isdir(new_path):
            return new_path
        else:
            os.mkdir(new_path)
    except Exception as e:
        print "Can't to mkdir " , new_path,'\n',str(e)
        sys.exit(1)
    return new_path
    
    
def print_all(path):
    sum=0
    for s in get_rules(path):
        print s
        c = raw_input("Go_Next:Y is Yes to go. Other is !!EXIT!! Print_all\n")
        if c not in ['y','Y']:
            break
        with open(s) as r:
            rules = []
            for line in r:
                
                rule = IDS_RULE().fill_rule(line)
                rules.append(rule)
                # print '\n'
            
            # rules1=[]
            # rules2=[]
            
            # 1.Adobe Flash Player
            # 2.PDF Reader
            # for rx in rules:
                # if "Flash" in rx.msg or "flash" in rx.msg:
                    # rules1.append(rx)
                # else:
                    # rules2.append(rx)
                    
            
            print len(rules)
            sum+=len(rules)
            print '"evm_netthreat_'+',"evm_netthreat_'.join([ru.sid+'"' for ru in rules])
            # print '"evm_netthreat_'+',"evm_netthreat_'.join([ru.sid+'"' for ru in rules2])
    return sum

    
def get_rules_by_pri(path,pri):
    new_path = mk_new_dir(path)
    sum=0
    sum_pri=0
    for s in get_rules(path):
        print s
        # c = raw_input("Go_Next:Y is Yes to go. Other is !!EXIT!! Print_all\n")
        # if c not in ['y','Y']:
            # break
        rules_lines = []
        rules = []
        rules_pri = []
        with open(s) as r:
            for line in r:
                rule = IDS_RULE().fill_rule(line)
                rules.append(rule)
                if rule.priority == str(pri):
                    rules_pri.append(rule)
                    rules_lines.append(line)
            
        ss = os.path.basename(s).rsplit('.',1)
        
        new_name = ss[0]+'-'+str(pri)+"."+ss[1]
        
        with open(os.path.join(new_path,new_name),'w') as w:
            w.writelines(rules_lines)
        
        
        print "The ",pri, "level of rules in ", s, "was writen to " ,new_name 
        print len(rules)
        print len(rules_pri)
        
        print "*" * 80
            
        sum+=len(rules)
        sum_pri+=len(rules_pri)
            
        
        
            # print '"evm_netthreat_'+',"evm_netthreat_'.join([ru.sid+'"' for ru in rules])
            # print '"evm_netthreat_'+',"evm_netthreat_'.join([ru.sid+'"' for ru in rules2])
    print "%d/%d" % (sum_pri,sum)
    return sum_pri
    
    

if __name__ == "__main__":
    s = 'alert tcp any 1024: -> $HOME_NET any (msg:"ATTACK_RESPONSE Unusual FTP Server Banner on High Port (StnyFtpd)";  flow:established,from_server; dsize:<30; content:"220 StnyFtpd"; depth:12; offset:0; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2007726; classtype:trojan-activity; priority:1; sid:4080006; rev:15052;)'
    
    rule = IDS_RULE()
    
    rule.fill_rule(s)
    print "test:"
    print rule
    print rule.attr
    print rule.kattr
    print rule.reference
    
    pathx = r'C:\Users\LRong\Desktop\IDS\high'
    pathy = r"D:\PyWork\IDSHandler\rules"
    
    
    path = pathy
    
    
    pri = str(2)
    if len(sys.argv)==2:
        path = sys.argv[1]
    if len(sys.argv)==3:
        path = sys.argv[1]
        pri = sys.argv[2]
    
    get_rules_by_pri(path,pri)
    print print_all(mk_new_dir(path))
    
