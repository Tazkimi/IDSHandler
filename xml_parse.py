#! /usr/bin/python
# -*- coding:utf-8 -*-

"""
    @author: lightk
    @date:2018/04/12
    @filename:xml_parse.py
    #XML解析类
    @功能-结点的增删改查
"""

import sys
import os.path
try:
    import xml.etree.CElementTree as ET
except:
    import xml.etree.ElementTree as ET

class XmlParse():
    def __init__(self, file_path):
        self.tree = None
        self.root = None
        self.xml_file_path = file_path

    def ReadXml(self):
        try:
            print("xmlfile:", self.xml_file_path)
            self.tree = ET.parse(self.xml_file_path)
            self.root = self.tree.getroot()
        except Exception as e:
            print ("parse xml faild!")
            sys.exit()
        else:
            print ("parse xml success!")
        finally: 
            return self.tree
               
    def CreateNode(self, tag, attrib, text):
        element = ET.Element(tag, attrib)
        element.text = text
        print ("tag:%s;attrib:%s;text:%s" %(tag, attrib, text))
        return element
              
    def AddNode(self, Parent, tag, attrib, text):
        element = self.CreateNode(tag, attrib, text)
        if Parent:
            Parent.append(element)
            el in self.root.iter("books")
            print (el.tag, "----", el.attrib, "----", el.text)
        else:
            print ("parent is none")

    def WriteXml(self, destfile):
        dest_xml_file = os.path.abspath(destfile)
        self.tree.write(dest_xml_file, encoding="utf-8",xml_declaration=True)

#遍历xml文件
def traverseXml(element):
    print (len(element))
    if len(element)>0:
        for child in element:
            print (child.tag, "----", child.attrib)
            traverseXml(child)
    # else:
        # print (element.tag, "----", element.attrib)

if __name__ == "__main__":
    
    xpath = r"D:\SVNRep\td\kb\ep\jointanalysis\common\net_threat_rules.xml"
    xml_file = os.path.abspath(xpath)
    parse = XmlParse(xml_file)
    tree = parse.ReadXml()
    root = tree.getroot()
    print(root)
    
    traverseXml(root)
    
    
    #修改xml文件，将passwd修改为999999
    # login = root.find("login")
    # passwdValue = login.get("passwd")
    # print ("not modify passwd:", passwdValue)
    # login.set("passwd", "999999")   #修改，若修改text则表示为login.text
    # print ("modify passwd:", login.get("passwd"))
    # parse.AddNode(root, "Python", {"age":"22", "hello":"world"}, "YES")
    # parse.WriteXml("testtest.xml")
    
    # for elem in tree.iter(): DFS全部元素
    # for elem in tree.iter(tag='branch')
    
    # for elem in tree.iterfind('branch/sub-branch'):  带有find只能查找儿子元素，孙不会去查。
    # for elem in tree.iterfind('branch[@name="release01"]'):
    
    
    
    
    
    