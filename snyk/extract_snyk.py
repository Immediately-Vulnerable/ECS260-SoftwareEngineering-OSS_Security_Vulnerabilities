import os, json, csv
import pandas as pd


def fetch_vuln(package_name, package_version):
    """
    Todo: add try-catch and timeout, try subprocess
    """

    # vuln_file = "vuln_{}.json".format(package_name)

    # command = "snyk test {}@{} --json-file-output={}".format(package_name, package_version, vuln_file)
    command = "snyk test {}@{} --json".format(package_name, package_version)

    stream = os.popen(command)
    vuln_json = json.load(stream)

    # with open(vuln_file, "r") as read_file:
    #     vuln_data = json.load(read_file)

    return vuln_json


def extract_vuln(vuln_json):
    """
    return[is_ok, num_vuln, critical_sev, high, medium, low]
    """

    res = []

    is_ok = vuln_json["ok"]
    res.append(is_ok)
    if is_ok:
        return res

    num_vuln = len(vuln_json["vulnerabilities"])
    res.append(num_vuln)

    sev_map = vuln_json["severityMap"]
    res.extend([sev_map["critical"], sev_map["high"], sev_map["medium"], sev_map["low"]])

    # for i in range(num_vuln):
    #     fixed_ver = vuln_json["vulnerabilities"][i]["fixedIn"]
   
    return res

def test():
    """
    Test fetch and extract vulnurability functions.
    """
    vuln_json = fetch_vuln("jquery-ui", "1.12.0") # bad package
    vuln_json = fetch_vuln("1-1-help-desk-system", "0.0.7") # worse package
    vuln_json = fetch_vuln("node-red-contrib-join-wait", "0.3.0") # good package
    vuln_arr = extract_vuln(vuln_json)
    return vuln_arr



dir = "/Users/Nan/projects/ECS260/snyk/data/npm/"
proj_fname = dir + "(NPM_extracted)projects_with_repository_fields-1.6.0-2020-01-12.csv"
vuln_fname = dir + "project_vuln_sample.csv"
samples = 100

# version_dic = {}
# counter = 0
# with open(proj_fname, "r") as csvfile:
#   datareader = csv.reader(csvfile)
#   next(datareader)  # yield the header row
#   for row in datareader:
#     id = row[0]
#     name = row[2]
#     version = row[13]
#     version_dic[id] = (name, version)
#     counter += 1
#     if counter > samples:
#         break

# for this_id, (name, version) in version_dic.items():
#     print (this_id, name, version)
#     output_arr = [this_id, name, version]
#     this_vuln_json = fetch_vuln(name, version)
#     this_vuln_arr = extract_vuln(this_vuln_json)
#     output_arr.extend(this_vuln_arr)
#     print(", ".join(map(str, output_arr)))

counter = 0
header_out = ["id", "name", "version", "is_ok", "num_vuln", "critical", "high", "medium", "low"]
with open(vuln_fname, 'w') as outfile, open(proj_fname, 'r') as infile:
    datareader = csv.reader(infile)
    next(datareader)  # yield the header row
    outfile.write(", ".join(map(str, header_out)) + "\n") # write header row
    for row in datareader:
        id = row[0]
        name = row[2]
        version = row[13]
        print (id, name, version)
        output_arr = [id, name, version]
        this_vuln_json = fetch_vuln(name, version)
        this_vuln_arr = extract_vuln(this_vuln_json)
        output_arr.extend(this_vuln_arr)
        outfile.write(", ".join(map(str, output_arr)) + "\n") 

        counter += 1
        if counter > samples:
            break

