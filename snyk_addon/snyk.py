"""
Trying out snyk data extraction
"""

import csv
from dateutil import parser


class ExtractSnykData:
    def __init__(self):
        pass

    @staticmethod
    def strip_chars(input_string, chars_to_strip):
        output_string = input_string
        for char in chars_to_strip:
            output_string = str(output_string).replace(char, ' ')
        return output_string

    @staticmethod
    def write_to_csv(data, headers, filename):
        output_file = open(filename, "w")
        writer = csv.writer(output_file)

        data.insert(0, headers)


        for row in data:
            writer.writerow(row)
        output_file.close()
        """
        with open(filename, 'w') as output_file:
            writer = csv.Writer(output_file, fieldnames=headers)
            writer.writeheader()
            writer.writerow(data)
        """
        print("Data written to [" + filename + "].")
        return True

    @staticmethod
    def check_negative(s):
        try:
            f = float(s)
            if (f < 0):
                return True
            # Otherwise return false
            return False
        except ValueError:
            return False

    def calculate_vulnerability_statistics(self):
        print("Extracting Snyk Vulnerability Data")
        input_file_loc = "../data/vuln-20211127T093052Z-001/vuln/top_2000_package_release_vulnCount_had_vuln_vulnDetails.csv"
        output_file_name = "vulnerability_statistics.csv"
        reader = csv.DictReader(open(input_file_loc), delimiter='\t')
        count = 0
        exit_count = 1000000000000000
        result_set = []
        severity_dataset = {}  # Mapped -> severity
        #result_set_severity = []  # Mapped -> severity
        vulnerability_type_dataset = {}  # Mapped -> Vulnerability Type (Title)
        result_set_headers = ['Package Name', 'Release Version', 'Release Time',
                              'Publication Time', 'Delta Days', 'Severity', 'Vulnerability Type']
        unwanted_datetime_chars = "TZ"
        unwanted_fixedIn_chars = "[]"
        print("Processing records....")
        for row in reader:
            #print(str(row) + " | " + str(type(row)))
            row_writer = []

            row_writer_vulnerability_type = []
            print("Record No.: " + str(count+1))
            rank = int(row['Rank'])
            package_name = str(row['Name'])
            release_name = str(row['Release.Name'])
            release_time = parser.parse(self.strip_chars(str(row['Release.Time']), unwanted_datetime_chars))
            publication_time = parser.parse(self.strip_chars(str(row['publicationTime']), unwanted_datetime_chars))
            delta_time = publication_time - release_time  # <-- Use this, it is more honest
            #delta_time_days = abs(delta_time.days)
            delta_time_days = delta_time.days
            severity = str(row['severity'])
            vulnerability_type = str(row['title'])
            fixed_in = self.strip_chars(str(row['fixedIn']), unwanted_fixedIn_chars).strip(" ")
            """
            is_upgradable = str(row['isUpgradable'])
            is_patchable = str(row['isPatchable'])
            is_pinnable = str(row['isPinnable'])
            """
            if str(row['isUpgradable']) == 'True':
                is_upgradable = True
            else:
                is_upgradable = False
            if str(row['isPatchable']) == 'True':
                is_patchable = True
            else:
                is_patchable = False
            if str(row['isPinnable']) == 'True':
                is_pinnable = True
            else:
                is_pinnable = False
            vulnerability_depth_count = int(row['pathDepth'])
            vulnerability_index = int(row['vulnIndex'])

            """
            print("Rank: " + str(rank))
            print("Package Name: " + package_name)
            print("Release Name: " + release_name)
            print("Release Time: " + str(release_time))
            print("Publication Time: " + str(publication_time))
            print("Delta Days: " + str(delta_time_days))
            print("Severity: " + severity)
            print("Vulnerability Type: " + vulnerability_type)
            print("Fixed In: " + str(fixed_in) + " | Type: " + str(type(fixed_in)) + " | Length: " + str(len(fixed_in)))
            print("Is Upgradable: " + str(is_upgradable) + " | Type: " + str(type(is_upgradable)))
            print("Is Patchable: " + str(is_patchable))
            print("Is Pinnable:" + str(is_pinnable))
            print("Vulnerability Depth Count: " + str(vulnerability_depth_count) + " | Type: " + str(type(vulnerability_depth_count)))
            print("Vulnerability Index: " + str(vulnerability_index))
            print("*"*20)
            if self.check_negative(delta_time_days):
                pass
                #print("Delta is negative!!!!")
                #exit(1)
            """

            # Calculate Severity-based Statistics
            if severity not in severity_dataset:
                severity_dataset[severity] = {}

            if 'delta_days_avg' not in severity_dataset[severity]:
                severity_dataset[severity]['delta_days_avg'] = delta_time_days
            else:
                severity_dataset[severity]['delta_days_avg'] = (severity_dataset[severity]['delta_days_avg'] + delta_time_days)/2

            if 'vulnerability_index_avg' not in severity_dataset[severity]:
                severity_dataset[severity]['vulnerability_index_avg'] = vulnerability_index
            else:
                severity_dataset[severity]['vulnerability_index_avg'] = (severity_dataset[severity]['vulnerability_index_avg'] + vulnerability_index)/2

            if 'rank_avg' not in severity_dataset[severity]:
                severity_dataset[severity]['rank_avg'] = rank
            else:
                severity_dataset[severity]['rank_avg'] = (severity_dataset[severity]['rank_avg'] + rank)/2

            if 'vulnerability_depth_count_avg' not in severity_dataset[severity]:
                severity_dataset[severity]['vulnerability_depth_count_avg'] = vulnerability_depth_count
            else:
                severity_dataset[severity]['vulnerability_depth_count_avg'] = (severity_dataset[severity]['vulnerability_depth_count_avg'] + vulnerability_depth_count)/2

            if 'is_upgradable_true_count' not in severity_dataset[severity]:
                if is_upgradable:
                    severity_dataset[severity]['is_upgradable_true_count'] = 1
                else:
                    severity_dataset[severity]['is_upgradable_true_count'] = 0
            else:
                if is_upgradable:
                    severity_dataset[severity]['is_upgradable_true_count'] += 1

            if 'is_patchable_true_count' not in severity_dataset[severity]:
                if is_patchable:
                    severity_dataset[severity]['is_patchable_true_count'] = 1
                else:
                    severity_dataset[severity]['is_patchable_true_count'] = 0
            else:
                if is_patchable:
                    severity_dataset[severity]['is_patchable_true_count'] += 1

            if 'is_pinnable_true_count' not in severity_dataset[severity]:
                if is_pinnable:
                    severity_dataset[severity]['is_pinnable_true_count'] = 1
                else:
                    severity_dataset[severity]['is_pinnable_true_count'] = 0
            else:
                if is_pinnable:
                    severity_dataset[severity]['is_pinnable_true_count'] += 1

            if 'fixed_in_true_count' not in severity_dataset[severity]:
                if len(fixed_in) != 0:
                    severity_dataset[severity]['fixed_in_true_count'] = 1
                else:
                    severity_dataset[severity]['fixed_in_true_count'] = 0
            else:
                if len(fixed_in) != 0:
                    severity_dataset[severity]['fixed_in_true_count'] += 1

            if 'fixed_in_false_count' not in severity_dataset[severity]:
                if len(fixed_in) == 0:
                    severity_dataset[severity]['fixed_in_false_count'] = 1
                else:
                    severity_dataset[severity]['fixed_in_false_count'] = 0
            else:
                if len(fixed_in) == 0:
                    severity_dataset[severity]['fixed_in_false_count'] += 1

            # Calculate Vulnerability Type (aka Title) based Statistics


            if vulnerability_type not in vulnerability_type_dataset:
                vulnerability_type_dataset[vulnerability_type] = {}

            if 'delta_days_avg' not in vulnerability_type_dataset[vulnerability_type]:
                vulnerability_type_dataset[vulnerability_type]['delta_days_avg'] = delta_time_days
            else:
                vulnerability_type_dataset[vulnerability_type]['delta_days_avg'] = (vulnerability_type_dataset[vulnerability_type]['delta_days_avg'] + delta_time_days) / 2

            if 'vulnerability_index_avg' not in vulnerability_type_dataset[vulnerability_type]:
                vulnerability_type_dataset[vulnerability_type]['vulnerability_index_avg'] = vulnerability_index
            else:
                vulnerability_type_dataset[vulnerability_type]['vulnerability_index_avg'] = (vulnerability_type_dataset[vulnerability_type]['vulnerability_index_avg'] + vulnerability_index) / 2

            if 'rank_avg' not in vulnerability_type_dataset[vulnerability_type]:
                vulnerability_type_dataset[vulnerability_type]['rank_avg'] = rank
            else:
                vulnerability_type_dataset[vulnerability_type]['rank_avg'] = (vulnerability_type_dataset[vulnerability_type]['rank_avg'] + rank) / 2

            if 'vulnerability_depth_count_avg' not in vulnerability_type_dataset[vulnerability_type]:
                vulnerability_type_dataset[vulnerability_type]['vulnerability_depth_count_avg'] = vulnerability_depth_count
            else:
                vulnerability_type_dataset[vulnerability_type]['vulnerability_depth_count_avg'] = (vulnerability_type_dataset[vulnerability_type][
                                                                                                       'vulnerability_depth_count_avg'] + vulnerability_depth_count) / 2

            if 'is_upgradable_true_count' not in vulnerability_type_dataset[vulnerability_type]:
                if is_upgradable:
                    vulnerability_type_dataset[vulnerability_type]['is_upgradable_true_count'] = 1
                else:
                    vulnerability_type_dataset[vulnerability_type]['is_upgradable_true_count'] = 0
            else:
                if is_upgradable:
                    vulnerability_type_dataset[vulnerability_type]['is_upgradable_true_count'] += 1

            if 'is_patchable_true_count' not in vulnerability_type_dataset[vulnerability_type]:
                if is_patchable:
                    vulnerability_type_dataset[vulnerability_type]['is_patchable_true_count'] = 1
                else:
                    vulnerability_type_dataset[vulnerability_type]['is_patchable_true_count'] = 0
            else:
                if is_patchable:
                    vulnerability_type_dataset[vulnerability_type]['is_patchable_true_count'] += 1

            if 'is_pinnable_true_count' not in vulnerability_type_dataset[vulnerability_type]:
                if is_pinnable:
                    vulnerability_type_dataset[vulnerability_type]['is_pinnable_true_count'] = 1
                else:
                    vulnerability_type_dataset[vulnerability_type]['is_pinnable_true_count'] = 0
            else:
                if is_pinnable:
                    vulnerability_type_dataset[vulnerability_type]['is_pinnable_true_count'] += 1

            if 'fixed_in_true_count' not in vulnerability_type_dataset[vulnerability_type]:
                if len(fixed_in) != 0:
                    vulnerability_type_dataset[vulnerability_type]['fixed_in_true_count'] = 1
                else:
                    vulnerability_type_dataset[vulnerability_type]['fixed_in_true_count'] = 0
            else:
                if len(fixed_in) != 0:
                    vulnerability_type_dataset[vulnerability_type]['fixed_in_true_count'] += 1

            if 'fixed_in_false_count' not in vulnerability_type_dataset[vulnerability_type]:
                if len(fixed_in) == 0:
                    vulnerability_type_dataset[vulnerability_type]['fixed_in_false_count'] = 1
                else:
                    vulnerability_type_dataset[vulnerability_type]['fixed_in_false_count'] = 0
            else:
                if len(fixed_in) == 0:
                    vulnerability_type_dataset[vulnerability_type]['fixed_in_false_count'] += 1


            """
            row_writer.append(package_name)
            row_writer.append(release_name)
            row_writer.append(str(release_time))
            row_writer.append(str(publication_time))
            row_writer.append(str(delta_time_days))
            row_writer.append(severity)
            row_writer.append(vulnerability_type)
            result_set.append(row_writer)
            """

            count += 1
            if count == exit_count:
                break
        print("Total number of records: " + str(count))

        # Write Severity Dataset to CSV

        severity_headers = ['Severity', 'Delta Days', 'Average Vulnerability Index', 'Average Rank', 'Average Vulnerability Depth Count',
                            'Is Upgradable Count', 'Is Patchable Count', 'Is Pinnable Count', 'Vulnerabilities Fixed', 'Vulnerabilities Not Fixed']
        
        output_file_name = "severity_dataset_analysis.csv"
        output_file = open(output_file_name, "w")
        writer = csv.writer(output_file)
        writer.writerow(severity_headers)

        for severity in severity_dataset:
            severity_row = []
            severity_row.append(severity)
            severity_row.append(severity_dataset[severity]['delta_days_avg'])
            severity_row.append(severity_dataset[severity]['vulnerability_index_avg'])
            severity_row.append(severity_dataset[severity]['rank_avg'])
            severity_row.append(severity_dataset[severity]['vulnerability_depth_count_avg'])
            severity_row.append(severity_dataset[severity]['is_upgradable_true_count'])
            severity_row.append(severity_dataset[severity]['is_patchable_true_count'])
            severity_row.append(severity_dataset[severity]['is_pinnable_true_count'])
            severity_row.append(severity_dataset[severity]['fixed_in_true_count'])
            severity_row.append(severity_dataset[severity]['fixed_in_false_count'])
            writer.writerow(severity_row)
        output_file.close()

        # Write Severity Dataset to CSV

        vulnerability_type_headers = ['Vulnerability Type', 'Delta Days', 'Average Vulnerability Index', 'Average Rank', 'Average Vulnerability Depth Count',
                                      'Is Upgradable Count', 'Is Patchable Count', 'Is Pinnable Count', 'Vulnerabilities Fixed', 'Vulnerabilities Not Fixed']
        output_file_name = "vulnerability_type_dataset_analysis.csv"
        output_file = open(output_file_name, "w")
        writer = csv.writer(output_file)
        writer.writerow(vulnerability_type_headers)

        for vulnerability_type in vulnerability_type_dataset:
            vulnerability_type_row = []
            vulnerability_type_row.append(vulnerability_type)
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['delta_days_avg'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['vulnerability_index_avg'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['rank_avg'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['vulnerability_depth_count_avg'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['is_upgradable_true_count'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['is_patchable_true_count'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['is_pinnable_true_count'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['fixed_in_true_count'])
            vulnerability_type_row.append(vulnerability_type_dataset[vulnerability_type]['fixed_in_false_count'])
            writer.writerow(vulnerability_type_row)
        output_file.close()


        # Add code

        """
        output_file = open(filename, "w")
        writer = csv.writer(output_file)

        data.insert(0, headers)
       
        
        for row in data:
            writer.writerow(row)
        output_file.close()
        """
        #print(result_set)
        #self.write_to_csv(result_set, result_set_headers, output_file_name)
        #self.write_to_csv(severity_dataset, severity_headers, output_file_name)
        print("Done.")

    def extract_snyk_data(self):
        print("Extracting Snyk Vulnerability Data")
        """
        For reference: ./snyk test vue-server-renderer@2.2.0-beta.1 --json (use later)
        """
        input_file_loc = "../data/vuln-20211127T093052Z-001/vuln/top_2000_package_release_vulnCount.csv"
        reader = csv.DictReader(open(input_file_loc))
        count = 0
        for row in reader:
            print(str(row) + " | " + str(type(row)))
            count += 1
        print("Total number of records: " + str(count))


if __name__ == '__main__':
    #ExtractSnykData().extract_data()
    ExtractSnykData().calculate_vulnerability_statistics()

