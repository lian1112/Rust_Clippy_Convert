#coding=utf-8

#通过解析xml文件

import xml.etree.ElementTree as ET
import os
import sys
import getopt
import json
import re

issues_list = []
sources_list = []
header = {}

def print_usage():
    
    print 'Convert.py usage:'
    print '-i: The file to be converted, default is input.txt in current directory'
    print '-o: The json file to output, default is output.json in current directory'
    print '-h, Help Message'
	
	


if __name__ == "__main__":

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:", )
    except getopt.GetoptError, err:
        print str(err)
        print_usage()
        sys.exit(1)
    except:
        print "Unknown exception"
        sys.exit(2)

    # Parse the command line
    for option, value in opts:
        if option == "-i":
            input_file = value
        elif option == "-o":
            output_file = value
        elif option == "-h":
            print_usage()
            sys.exit(0)
		
		
    xmlFilePath = os.path.abspath(input_file)
    print xmlFilePath 
    try:
        tree = ET.parse(xmlFilePath)
        #print "tree type:", type(tree) 
    
        # 获得根节点
        root = tree.getroot()
    except Exception as e:  #捕获除与程序退出sys.exit()相关之外的所有异常
        print "parse test.xml fail!"
        sys.exit()
    print "root type:", type(root)   
    print root.tag, "----", root.attrib
    
    #遍历root的下一层
    for child in root:
        #print "visit file tag ----", child.attrib
        coverity_file_name = child.get("name")
        #coverity_file_name.replace("\\", "/")
        #p=os.popen("cd")
        #prefix = p.read() 
        prefix =os.getcwd()
        #print prefix
        #print len(prefix)
        #print coverity_file_name
        prefix = prefix+'\\'
        coverity_file_name = coverity_file_name.replace(prefix, '')
        coverity_file_name = coverity_file_name.replace('\\', '/')
        print coverity_file_name
        for violation in child:
            #print "visit violation tag ----", violation.attrib
            #print "visit violation value ----", violation.text
            coverity_line = violation.get("beginline")
			#<a href="超链接地址">Json字符串</>
            coverity_longDescription = "beginline:"+violation.get("beginline")+" "+"endline:"+violation.get("endline")+" "+"begincolumn:"+violation.get("begincolumn")+" "+"endcolumn:"+violation.get("endcolumn")+" "+"package:"+violation.get("package")+" "+"class:"+violation.get("class")+"<br>"+"<a href="+violation.get("externalInfoUrl")+">"+violation.get("externalInfoUrl")
            #coverity_longDescription = "beginline:"+violation.get("beginline")+" "+"endline:"+violation.get("endline")+" "+"begincolumn:"+violation.get("begincolumn")+" "+"endcolumn:"+violation.get("endcolumn")+" "+"package:"+violation.get("package")+" "+"class:"+violation.get("class")+" "+violation.get("externalInfoUrl")
            coverity_description = violation.text
            coverity_type = violation.get("rule")
            coverity_subcategory = violation.get("ruleset")
            coverity_function = violation.get("method")
            coverity_url = violation.get("externalInfoUrl")
            coverity_category = ""
            coverity_impact = ""
			
            if violation.get("priority") == "1":
                coverity_category = "severity error" 
                coverity_impact = "High"
            elif violation.get("priority") == "2":
                coverity_category = "severity error" 
                coverity_impact = "Medium"
            elif violation.get("priority") == "3":
                coverity_category = "severity warning" 
                coverity_impact = "High"
            elif violation.get("priority") == "4":
                coverity_category = "severity warning" 
                coverity_impact = "Medium"
            elif violation.get("priority") == "5":
                coverity_category = "severity information" 
                coverity_impact = "Medium"
				
            event_list = []
            event = {"tag": "event", "main": True, "file": coverity_file_name, "line": int(coverity_line), "description": coverity_description}
            event_list.append(event)
            
            properties = {"type": coverity_type, "category": coverity_category, "impact": coverity_impact, "cwe": None, "longDescription": coverity_longDescription, "localEffect": coverity_type, "issueKind": "QUALITY"}
            
            issue = {"checker": "PMD", "function": coverity_function, "file": coverity_file_name, "extra": coverity_url, "properties": properties, "events": event_list, "subcategory": coverity_subcategory}
            issues_list.append(issue)
            
            is_exist = False
            for d in sources_list:
                if d["file"] == coverity_file_name:
                    is_exist = True
            if not is_exist:
                source = {"file": coverity_file_name, "encoding": "ASCII"}
                sources_list.append(source)
			
    header["format"] = "cov-import-results input"
    header["version"] = 1

    json_str = {"header": header, "sources": sources_list, "issues": issues_list}

    with open(output_file, 'w') as f_out:
        f_out.write(json.dumps(json_str, indent=3))      
            
