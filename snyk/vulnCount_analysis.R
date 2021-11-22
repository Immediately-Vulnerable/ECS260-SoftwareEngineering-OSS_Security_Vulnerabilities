#### Set wd etc. ####
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
library(dplyr)
library(ggplot2)
library(reshape2)

#### Input setup ####
filename_vulnCount <- "top_2000_package_release_vulnCount.csv"
vulnCount <- read.csv(filename_vulnCount,
                      header = TRUE, as.is = TRUE, 
                      strip.white = TRUE, comment.char = "")
any(is.na(vulnCount$Name))
any(is.na(vulnCount$Release.Name))
any(is.na(vulnCount$Release.Time))
table(vulnCount$is_ok, useNA = "ifany")


#### Seperate err data ####
vulnCount_err <- vulnCount[vulnCount$is_ok == "error", ]
write.csv(vulnCount_err, "top_2000_package_release_vulnCount_err.csv",
          quote = FALSE, row.names = FALSE)

vulnCount_hasdata <- vulnCount[vulnCount$is_ok != "error", ]
table(vulnCount_hasdata$num_vuln, useNA = "ifany")
vulnCount_hasdata$num_vuln <- as.integer(vulnCount_hasdata$num_vuln)
write.csv(vulnCount_hasdata, "top_2000_package_release_vulnCount_hasdata.csv",
          quote = FALSE, row.names = FALSE)

vulnCount_hadVuln <- vulnCount_hasdata[vulnCount_hasdata$is_ok == "False", ]
write.csv(vulnCount_hadVuln, "top_2000_package_release_vulnCount_had_vuln.csv",
          quote = FALSE, row.names = FALSE)

#### Sort good data by release timestamp ####
vulnCount_hasdata$Release.Time <- as.Date(vulnCount_hasdata$Release.Time)
