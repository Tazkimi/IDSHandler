#! /usr/bin/python
# -*- coding:utf-8 -*-

"""
# @author: lightk
# @date:2018/04/08
# @filename:EP_rule_handler.py
"""

import os,re,sys
from collections import defaultdict
from EP_rule_model import JOINT_RULE
try:
    import xml.etree.CElementTree as ET
except:
    import xml.etree.ElementTree as ET
    
def get_rules(path):
    for f in os.listdir(path):
        rupath = os.path.join(path, f)
        if os.path.isfile(rupath) and f.endswith("_rules.xml"):
            yield rupath
        elif os.path.isdir(rupath):
            for p in get_rules(rupath):
                yield p

def print_all(path):
    group_d = defaultdict(list)
    print u"规则文件:" #.decode('utf-8').encode("gb2312")
    for s in get_rules(path):
        print '-'*4,os.path.basename(s)
        try:
            tree = ET.parse(s)
            root = tree.getroot()
            # rules = []
            for joint in root:
                rule = JOINT_RULE().fill_rule(root,joint)
                group_d[root.get('id')].append(rule)
        except ET.ParseError as e:
            print e,'\n','#######',s

        

    sum = 0
    print "*" * 80
    for k,v in group_d.iteritems():
        m = len(v)
        sum+=m
        print '-'*60
        print v[0].groupName,":",m
        for r in v:
            print '-'*4,r.id,":", r.name
            r.basic_check()
            
            
            print '--'*4,'-->'.join([x["name"] for x in r.detail.states])
            # print '---'*4,'\n'.join([x["eventFilter"] for x in r.detail.states])
            
            
            
    print '#'*70
    print u"规则总数:",sum


def get_file_rules(p):
    e_rules = []
    with open(p,'r') as r:
        for line in r:
            line.strip()
            e_rules.append(line.strip())
    return e_rules
    
    
def get_match(path,e_path):
    group_d = defaultdict(list)
    # print u"规则文件:" #.decode('utf-8').encode("gb2312")
    for s in get_rules(path):
        # print '-'*4,os.path.basename(s)
        try:
            tree = ET.parse(s)
            root = tree.getroot()
            # rules = []
            for joint in root:
                rule = JOINT_RULE().fill_rule(root,joint)
                group_d[root.get('id')].append(rule)
        except ET.ParseError as e:
            print e,s

    # print "*" * 80
    
    no_rules = get_file_rules(e_path)
    results = defaultdict(str)
    
    
    for k,v in group_d.iteritems():
        # print '-'*60
        # print v[0].groupName
        for r in v:
            # print '-'*4,r.id,":", r.name
            r.basic_check()
            
            for states in r.detail.states:
                
                # print '--'*4,states["name"]
                
                rp = r"evm_netthreat_([\d]+)"
                state_rules = re.findall(rp,states["eventFilter"])
                
                if state_rules:
                    for rr in state_rules:
                        if rr in no_rules:
                            results[rr] = states["name"]
                            # print rr
                            # print states["eventFilter"]
                    
    print "match counts:%d/%d" % (len(results.keys()),len(no_rules))
    for dd in no_rules:
        
        if results[dd]:
            print dd,",",results[dd]
        else:
            print dd,",Is not in any EP rules"

            
if __name__ == "__main__":
    
    path = r'D:\SVNRep\td\kb\ep\jointanalysis'
    
    e_path = r"D:\PyWork\IDSHandler\disapear.txt"
    
    # print_all(path)
    get_match(path,e_path)
    
