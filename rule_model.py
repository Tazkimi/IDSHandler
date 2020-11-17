#! /usr/bin/python
# -*- coding:utf-8 -*-

"""
# @author: lightk
# @date:2018/04/08
# @filename:rule_model.py
"""

import re,sys
from collections import defaultdict


class IDS_RULE():

    def __init__(self):
        self.act = ''
        self.protcol = ''
        self.srcIp = ''
        self.srcPort = ''
        self.dstIp = ''
        self.dstPort = ''
        
        self.attr = ''
        
        self.msg = ''
        self.flow = ''
        self.content = []
        
        self.reference=defaultdict(list)
        self.classtype = ''
        self.priority = ''
        self.sid = ''
        self.rev = ''
        
        self.kattr = {"sid":"", "msg":'', "flow":'', 'content':[], "reference":[], 'classtype':'',"priority":'',"rev":''}
        

    def __str__(self):
        return "evm_netthreat_%s : %s" % (self.sid, self.msg)
        
    def fill_rule(self,text):
        p = r'^\s*?(alert)\s+?(\S+?)\s+?(\S+?)\s+?(\S+?)\s+?->\s+?(\S+?)\s+?(\S+?)\s*?\((.*)\)\s*$'
        m = re.search(p,text)
        if m:
            self.act = m.group(1)
            self.protcol = m.group(2)
            self.srcIp = m.group(3)
            self.srcPort = m.group(4)
            self.dstIp = m.group(5)
            self.dstPort = m.group(6)
            
            self.attr = m.group(7)
            
        if self.attr:
            attrs = self.attr.split(';')
            for k_v in attrs:
                if ':' in k_v:
                    k,v = k_v.split(":",1)
                    if k.strip() in self.kattr.keys():
                        if type(self.kattr[k.strip()])==str:
                            self.kattr[k.strip()] = v.strip()
                        else:
                            self.kattr[k.strip()].append(v.strip())
        
        
        self.msg = self.kattr['msg']
        self.flow = self.kattr['flow']
        self.content = self.kattr['content']

        try:
            self.reference.update({kr_vr.split(',')[0].strip():kr_vr.split(',',1)[1].strip() for kr_vr in self.kattr['reference']})
        except Exception as e:
            dd = {}
            for kr_vr in self.kattr['reference']:
                dd[kr_vr.split(',')[0].strip()] = kr_vr.split(',',1)[1].strip()
                self.reference.update(dd)
        
        self.classtype = self.kattr['classtype']
        self.priority = self.kattr['priority']
        self.sid = self.kattr['sid']
        self.rev = self.kattr['rev']
        
        return self

        
if __name__ == "__main__":
    s = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Blackhole Landing Page Eval Variable Obfuscation 2";  flow:established,to_client; content:"=|22|e|22 3B|"; content:"+|22|val|22|"; distance:0; pcre:"/\x2B\x22val\x22(\x3B|\x5D)/";  classtype:trojan-activity; priority:1; sid:4220068; rev:15619;)'
    
    rule = IDS_RULE()
    
    rule.fill_rule(s)
    
    print rule
    print rule.attr
    print rule.kattr
    
