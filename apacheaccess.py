#!/usr/bin/env python3
# Apache HTTP Server Access Log Parser
# Reference: https://httpd.apache.org/docs/2.4/ko/logs.html
import argparse
import calendar
import datetime
import json
import time
import sys
import os
import re

class Access:
    def __init__(self, log_line):
        log_line_split = log_line.split(" ")
        self.ip = log_line_split[0]
        self.identd = log_line_split[1]
        self.userid = log_line_split[2]

        # Parse datetime
        time_split = re.split("[/:]", log_line_split[3][1:])
        day = int(time_split[0])
        month_name = [name[:3] for name in calendar.month_name]
        month = list(month_name).index(time_split[1])
        year = int(time_split[2])
        hour = int(time_split[3])
        minute = int(time_split[4])
        second = int(time_split[5])
        if log_line_split[4][0] == "+":
            zone = datetime.timezone(datetime.timedelta(hours=int(log_line_split[4][1:3]), minutes=int(log_line_split[4][3:-1])))
        else:
            zone = datetime.timezone(datetime.timedelta(hours=int(log_line_split[4][1:3]), minutes=int(log_line_split[4][3:-1])))

        self.time = int(time.mktime(datetime.datetime(year, month, day, hour, minute, second, tzinfo=zone).timetuple()))
        self.method = log_line_split[5][1:]
        self.path = log_line_split[6]
        self.protocol = log_line_split[7][:-1]
        self.status = log_line_split[8]
        self.size = log_line_split[9]
        try:
            # Combined Log
            self.referer = log_line_split[10][1:-1]
            self.agent = log_line.split('"')[-2]
        except:
            # Common Log
            self.referer = None
            self.agent = None
    def json(self):
        return json.dumps(self.__dict__)

def parse(log):
    log_split = log.split('\n')
    result = []
    line = 0
    for log_line in log_split:
        try:
            if log_line.strip():
                result.append(Access(log_line.strip()))
            line += 1
        except:
            print("apacheaccess: Syntax error in line %d" % line, file=sys.stdout)
    return result

def main():
    # Set argparse
    parser = argparse.ArgumentParser(description="apacheaccess: Apache HTTP Server Access Log Parser")
    parser.add_argument("-i", "--input", dest="input_file", help="input from file")
    parser.add_argument("-o", "--output", dest="output_file", help="save the output to a file")
    args = parser.parse_args()

    # Input access log
    if args.input_file:
        if os.path.isfile(args.input_file):
            try:
                fp = open(args.input_file, "rt")
                log = fp.read()
                fp.close()
            except:
                print("apacheaccess: %s: Permission denied" % args.input_file, file=sys.stdout)
                exit(-1)
        else:
            print("apacheaccess: %s: No such file or directory" % args.input_file, file=sys.stdout)
            exit(-1)
    else:
        log = ""
        for stdin in sys.stdin:
            try:
                log += stdin
            except StopIteration:
                break

    # Parse access log
    access = parse(log)
    access_json = []
    for i in access:
        access_json.append(i.json())
    output = {i : access_json[i] for i in range(len(access_json))}
    output = json.dumps(output)

    # Print or save the result
    if args.output_file:
        try:
            fp = open(args.output_file, "wt")
            fp.write(output)
            fp.close()
        except:
            print("apacheaccess: %s: Permission denied" % args.output_file, file=sys.stdout)
            exit(-1)
    else:
        print(output)
    return 0

if __name__ == "__main__":
    exit(main())
