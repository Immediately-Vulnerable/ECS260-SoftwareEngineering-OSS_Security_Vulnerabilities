# set wd etc.
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
# install.packages("dplyr")
library(dplyr)

v_raw <- read.csv("github_releases.csv")
j_raw <- read.csv("top2kStars_from_top5kPR_releases.csv")

v_ide <- subset(v_raw, select = c("Name", "Release.Name"))
j_ide <- subset(j_raw, select = c("Name", "Release.Name"))

new_ide <- setdiff(j_ide, v_ide)

new_data <- left_join(new_ide, j_raw, by = c("Name", "Release.Name"))
write.csv(new_data, file = "top2kStars_from_top5kPR_releases_new.csv", quote = FALSE)

######
