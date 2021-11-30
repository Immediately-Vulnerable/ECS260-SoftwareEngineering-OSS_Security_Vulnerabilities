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



def extract_vuln_details(vuln_json):
    """
    colnames = ["is_ok", "vulnIndex", "creationTime", "disclosureTime", "modificationTime", "publicationTime",
                "severity", "title", "path", "pathDepth", "rootPackage", "rootPackageVersion" ,"upgradePath", "isUpgradable", "isPatchable", "isPinnable", "fixedIn", "semver"]
    Case 1: return [ "error" + "err message" ]
    Case 2: return [ "true" ]
    Case 3: return [ ["false", vulnIndex(int), creationTime, disclosureTime, modificationTime, publicationTime, 
                      severity, title, from/path(arr), pathDepth(int), rootPackage, rootPackageVersion, upgradePath(arr), isUpgradable, isPatchable, isPinnable, fixedIn, semver],
                     ...
                    ]       
    """

    # Case 1
    if "error" in vuln_json:
        return ["error " + vuln_json["error"]]
    
    # Case 2
    is_ok = vuln_json["ok"]
    if is_ok:
        return [is_ok]

    # Case 3
    num_vuln = len(vuln_json["vulnerabilities"])
    res = []
    for vulnIndex in range(0, num_vuln):
        this_vuln_res = []
        this_vuln_res.extend([is_ok, vulnIndex+1])

        this_vuln_json = vuln_json["vulnerabilities"][vulnIndex]
        this_vuln_res.extend([
                            this_vuln_json["creationTime"], this_vuln_json["disclosureTime"],
                            this_vuln_json["modificationTime"], this_vuln_json["publicationTime"],
                            this_vuln_json["severity"], this_vuln_json["title"], 
                            this_vuln_json["from"], len(this_vuln_json["from"]), 
                            this_vuln_json["name"], this_vuln_json["version"],
                            this_vuln_json["upgradePath"], this_vuln_json["isUpgradable"], 
                            this_vuln_json["isPatchable"], this_vuln_json["isPinnable"],
                            this_vuln_json["fixedIn"],this_vuln_json["semver"]
                            ])
        res.append(this_vuln_res)
    return res

def generate_vuln_details_file(in_fname, out_fname, errlog_fname, id_index, name_index, version_index, url_index, sample_size = None, skip = None):
    counter = 0
    header_out = ["id", "name", "version", "is_ok",
                  "vulnIndex", "creationTime", "disclosureTime", "modificationTime", "publicationTime",
                  "severity", "title", "path", "pathDepth", "rootPackage", "rootPackageVersion" ,"upgradePath", "isUpgradable", "isPatchable", "isPinnable", "fixedIn", "semver" ]
    
    with open(out_fname, 'w' if skip is None else 'a' ) as outfile, open(in_fname, 'r') as infile, open(errlog_fname, 'w') as errlog:
        datareader = csv.reader(infile)
        if skip is not None:
            for _ in range(skip):
                next(datareader)
        else:
            outfile.write("\t".join(map(str, header_out)) + "\n") # write header row
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
                this_vuln_mat = extract_vuln_details(this_vuln_json)
                if len(this_vuln_mat) == 1:
                    if str(this_vuln_mat[0]).startswith('error') or str(this_vuln_mat[0]).startswith('True') :
                        this_vuln_row = [str(this_vuln_mat[0])]
                    else:
                        this_vuln_row = [x for x in this_vuln_mat[0]]
                    output_arr.extend(this_vuln_row)
                    print("\t".join(map(str, output_arr[:5])))
                    outfile.write("\t".join(map(str, output_arr)) + "\n") 
                else:
                    for this_vuln_row in this_vuln_mat:
                        output_arr = [id, name, version]
                        output_arr.extend(this_vuln_row)
                        print("\t".join(map(str, output_arr[:5])))
                        outfile.write("\t".join(map(str, output_arr)) + "\n") 

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
    out_fname = dir + "output/{}_{}.tsv".format(raw_file, str(i))
    errlog_fname = out_fname.replace(".csv", "_err.txt")
    generate_vuln_details_file(in_fname, out_fname, errlog_fname, id_index=id_index, name_index=name_index, version_index=version_index, 
                                url_index=url_index, skip = skip, sample_size = sample_size)

def test():
    # vuln_json = fetch_vuln("react-dom", "15.7.0") 
    # vuln_json = fetch_vuln("office-ui-fabric-react", "6.199.0") # 5 vuln
    vuln_json = fetch_vuln("vue", "0.8.5") # error
    # vuln_json = fetch_vuln("vue-template-compiler", "0.1.0") # 0 vuln
    res = extract_vuln_details(vuln_json)
    print(res)
    print(len(res))

