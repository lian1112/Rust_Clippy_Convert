#coding=utf-8

#通过解析xml文件

import xml.etree.ElementTree as ET
import os
import sys
import getopt
import json
import re

issue = {}
issues_list = []
sources_list = []
header = {}
event_list = []
event = {}
properties = {}
json_str = {}
fileabspath = ''
line_number = ''
line_column = ''
coverity_description = ''
is_exist = False


def print_usage():
    
    print 'Convert.py usage:'
    print '-i: The file to be converted, default is input.txt in current directory'
    print '-o: The json file to output, default is output.json in current directory'
    print '-h, Help Message'
	
def add_event():
    global issue
    global issues_list
    global event
    global event_list
    global properties
    global fileabspath
    global line_number
    global line_column
    if event :
        event_list.append(event)
        issue = {"checker": "Go_Vet", "function": None, "file": fileabspath, "extra": coverity_description, "properties": properties, "events": event_list, "subcategory": coverity_description}
        issues_list.append(issue)
        event = {}
        event_list = []
        issue = {}
        properties = {}

        	


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
		
		
    absFilePath = os.path.abspath(input_file)
    #print absFilePath 
    file_object = open(absFilePath)
    try:
        file_content = file_object.read().splitlines()
        pattern = '(.*):([0-9]*):([0-9]*):'	
        for file_content_line in file_content :
            #print file_content_line
            if re.search(pattern, file_content_line) :
                add_event()
                prefix_file_content = re.search(pattern, file_content_line).group(0)
                filepath = re.search(pattern, file_content_line).group(1)
                fileabspath = os.getcwd()+'/'+filepath
                #print fileabspath
                #fileabspath = fileabspath.replace('/', '\\')
                #print fileabspath
                is_exist = False
                for d in sources_list:
                    if d["file"] == fileabspath:
                        is_exist = True
                if not is_exist:
                    source = {"file": fileabspath, "encoding": "ASCII"}
                    sources_list.append(source)
                coverity_description = file_content_line.lstrip(prefix_file_content).strip()
                line_number = re.search(pattern, file_content_line).group(2)
                #print line_number
                line_column = re.search(pattern, file_content_line).group(3)
                #print line_column	
                event = {"tag": "event", "main": True, "file": fileabspath, "line": int(line_number), "description": coverity_description}
                properties = {"type": "Go_Vet", "category": "Go_Vet", "impact": "Low", "cwe": None, "longDescription": coverity_description, "localEffect": "Go_Vet", "issueKind": "QUALITY"}
                
            elif not file_content_line.startswith('#') :
                coverity_description = coverity_description+file_content_line
                event = {"tag": "event", "main": True, "file": fileabspath, "line": int(line_number), "description": coverity_description}				
                properties = {"type": "Go_Vet", "category": "Go_Vet", "impact": "Low", "cwe": None, "longDescription": coverity_description, "localEffect": "Go_Vet", "issueKind": "QUALITY"}
        
        event_list.append(event)
        issue = {"checker": "Go_Vet", "function": None, "file": fileabspath, "extra": coverity_description, "properties": properties, "events": event_list, "subcategory": coverity_description}
        issues_list.append(issue)         
        header["format"] = "cov-import-results input"
        header["version"] = 1
        json_str = {"header": header, "sources": sources_list, "issues": issues_list}
        
    except Exception as e:  #捕获除与程序退出sys.exit()相关之外的所有异常
        print str(e)
        print "parse log fail!"
        sys.exit()
    finally:
        file_object.close()	
        with open(output_file, 'w') as f_out:
            f_out.write(json.dumps(json_str, indent=3)) 
