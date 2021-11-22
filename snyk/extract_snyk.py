import os, json, csv
import subprocess


def fetch_vuln(package_name, package_version, github_url = None):
    """
    Todo: add try-catch and timeout, try subprocess
    """
    MAX_RETRY = 10
    TIMEOUT = 60*3
    retry_counter = MAX_RETRY

    while retry_counter > 0:
        try:
            command = "snyk test {}@{} --json".format(package_name, package_version)
            r = subprocess.run(command, timeout=TIMEOUT, shell=True, capture_output=True)
            vuln_json = json.loads(r.stdout)
            if "error" in vuln_json and github_url is not None:
                command = "snyk test {} --json".format(github_url)
                r = subprocess.run(command, timeout=TIMEOUT, shell=True, capture_output=True)
                vuln_json = json.loads(r.stdout)
                return vuln_json
            return vuln_json
        except subprocess.TimeoutExpired as e:
            print(e)
            retry_counter -= 1
            print("{} retries left".format(retry_counter))
        except Exception as e:
            print(e)
            retry_counter -= 1
            print("{} retries left".format(retry_counter))

    if retry_counter == 0:
        raise Exception("Maxed out tries")
    return None



def extract_vuln(vuln_json):
    """
    return[is_ok, num_vuln, critical_sev, high, medium, low]
    """

    res = []

    if "error" in vuln_json:
        res.extend(["error", vuln_json["error"]])
        return res

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
    # vuln_json = fetch_vuln("jquery-ui", "1.12.0") # bad package
    # vuln_json = fetch_vuln("1-1-help-desk-system", "0.0.7") # worse package
    # vuln_json = fetch_vuln("node-red-contrib-join-wait", "0.3.0") # good package
    
    vuln_json = fetch_vuln("fsevents", "v1.2.1", "https://github.com/fsevents/fsevents/releases/tag/v1.2.1")
    vuln_arr = extract_vuln(vuln_json)
    return vuln_arr


def generate_vuln_file(in_fname, out_fname, errlog_fname, id_index, name_index, version_index, url_index, sample_size = None, skip = None):
    counter = 0
    header_out = ["id", "name", "version", "is_ok", "num_vuln", "critical", "high", "medium", "low"]
    with open(out_fname, 'w' if skip is None else 'a' ) as outfile, open(in_fname, 'r') as infile, open(errlog_fname, 'w') as errlog:
        datareader = csv.reader(infile)
        # next(datareader) # skip header  
        if skip is not None:
            for _ in range(skip):
                next(datareader)
        else:
            outfile.write(", ".join(map(str, header_out)) + "\n") # write header row
        try:
            for row in datareader:
                id = row[id_index]
                name = row[name_index]
                version = row[version_index]
                if url_index is not None:
                    url = row[url_index]
                else:
                    url = None
                output_arr = [id, name, version]
                
                this_vuln_json = fetch_vuln(name, version, url)
                this_vuln_arr = extract_vuln(this_vuln_json)
                output_arr.extend(this_vuln_arr)

                print(", ".join(map(str, output_arr)))
                outfile.write(", ".join(map(str, output_arr)) + "\n") 

                counter += 1
                if sample_size is not None and counter > sample_size:
                    break
                
        except Exception as e:
            errlog.write('index: {}, error msg:{} \n'.format(counter, str(e)))
        
        finally:
            outfile.close()
            infile.close()
            errlog.close()
    

def para_wrapper(raw_file, i, id_index, name_index, version_index, url_index = None, skip = None, sample_size = None):
    dir = "/Users/Nan/projects/ECS260/snyk/data/npm/"
    in_fname = dir + "split/{}_{}.csv".format(raw_file, str(i))
    out_fname = dir + "output/{}_{}.csv".format(raw_file, str(i))
    errlog_fname = out_fname.replace(".csv", "_err.txt")
    generate_vuln_file(in_fname, out_fname, errlog_fname, id_index=id_index, name_index=name_index, version_index=version_index, 
                        url_index=url_index, skip = skip, sample_size = sample_size)
