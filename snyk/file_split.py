import os
dir = "/Users/Nan/projects/ECS260/snyk/data/npm/"
raw_file = "top2kStars_from_top5kPR_releases.csv"
header = True

# def split_file(dir_in, dir_out, raw_file, header, splitLen = 5000):
#     in_fname = dir_in + raw_file

#     with open(in_fname, 'r') as infile:
#         if header:
#             next(infile)

#         counter_file = 1
#         with open(dir_out+raw_file.replace(".csv", counter_file + ".csv"), 'w') as outfile:
#             for i in range(0, splitLen):
#                 thisline = infile.read()
#                 outfile.write(thisline)
#             counter_file
