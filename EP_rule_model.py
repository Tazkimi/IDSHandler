#! /usr/bin/python
# -*- coding:utf-8 -*-

"""
# @author: lightk
# @date:2018/04/08
# @filename:EP_rule_model.py
"""

import re,sys
from collections import defaultdict

class JOINT_RULE():

    def __init__(self):
        self.gid = ''
        self.groupName = ''
        self.id = ''
        self.name = ''
        self.attackingStage = ''
        self.aggAlgo = ''
        
        self.ruleSettings = ''

        self.consequence = ''
        self.solution = ''
        self.detail=RULE_DETAIL()

    def __str__(self):
        return "%s/%s:" % (self.gid, self.id,self.name) #, self.namedecode("utf-8").encode("gb2312")
        
    def fill_rule(self,rootET,joinRuleET):
        self.gid = rootET.tag
        self.groupName = rootET.get("name")
        self.id = joinRuleET.get("id")
        self.name = joinRuleET.get("name")
        self.attackingStage = joinRuleET.get("attackingStage")
        self.aggAlgo = joinRuleET.get("aggAlgo")
        
        self.ruleSettings = joinRuleET.text.strip()
        try:
            self.detail = self.detail.fill_detail(self.ruleSettings)
        except Exception:
            print "A :To Check Is There Anything Wrong In RULE_DETAIL!!!\n"
            print self.ruleSettings
            x = raw_input("DDD")
            
        
        for attr in joinRuleET:
            if "consequence" == attr.get("name"):
                self.consequence =attr.text.strip()
            if "solution" == attr.get("name"):
                self.solution =attr.text.strip()
        
        self.ruleSettings = joinRuleET.text.strip()
        
        return self
        
    def basic_check(self):
        if not all([self.gid,self.groupName,self.id,self.name,self.attackingStage,self.aggAlgo,self.ruleSettings,self.consequence,self.solution]):
            print "K: To Check Is There Anything Wrong in JOINT_RULE !!!\n"
            print self.id
            x = raw_input("DDD")

        if not all([self.detail.idleTimeout,self.detail.maxLifeTime,self.detail.classtype,self.detail.level,self.detail.states]):
            print "B: To Check Is There Anything Wrong In RULE_DETAIL!!!\n"
            print self.detail
            x = raw_input("DDD")
        for states in self.detail.states:
            if not all([states["name"],states["eventFilter"],states.get('level','') or states.get("levelPromotions"), states.get("enterCriteria")]):
                print "C: To Check Is There Anything Wrong In RULE_DETAIL!!!\n"
                print states
                x = raw_input("DDD")
        

def text_dict(text):
    a = text.strip(" [\n")
    d = re.split("\n",a)
    # print d
    kv = {x.split(":")[0].strip(" \"\t',"):x.split(":")[1].strip(" \"\t',") for x in d if len(x.split(":"))>1}
    return kv
        
class RULE_DETAIL():

    def __init__(self):
        self.idleTimeout = ''
        self.maxLifeTime = ''
        self.classtype = ''
        self.level = ''
        self.states = []

        self.attr = defaultdict(str)

    def __str__(self):
        return "%s/%s" % (self.id,':'.join([x[name] for x in self.states]))

    def fill_detail(self,text):
        p = r'\s*settings\s*=\s*[\s\n]*\[(.*?)states\s*:\s*\[(.*)\][\s\n]*\]\s*$'
        g = re.search(p,text,re.DOTALL)
        
        if g:
            self.attr.update(text_dict(g.group(1)))
            g2 = g.group(2)
            gg2 = re.split(r'\]\s*\n\s*,\s*\[',g2)
            for x in gg2:
                self.states.append(text_dict(x))

        self.idleTimeout = self.attr.get('idleTimeout','')
        self.maxLifeTime = self.attr.get('maxLifeTime','')
        self.classtype = self.attr.get('classtype','')
        self.level = self.attr.get('level','')
        
        return self

if __name__ == "__main__":
    print "No IN TEST,JUST A MODOUL!!!"


