# set wd etc.
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
library(dplyr)

rawfile_name = "top_2000_package_release"
total_subfiles = 12

# rawfile_name = "missing_github_releases"
# total_subfiles = 8
# rawfile_name = "github_releases"
# total_subfiles = 9
# rawfile_name = "top2kStars_from_top5kPR_releases_new"
# total_subfiles = 8

dir_in = "./split"
dir_out = "./output"

raw <- read.csv(paste(rawfile_name, ".csv", sep = ""))
header_raw <- colnames(raw)


res <- NULL
missing <- NULL
for (i in 1: total_subfiles){
  filename_in = paste(dir_in, "/", rawfile_name, "_", i, ".csv", sep = "")
  filename_out = paste(dir_out, "/", rawfile_name, "_", i,".csv", sep = "")
  df_in <- read.csv(filename_in, header = FALSE, as.is = TRUE, 
                    strip.white = TRUE, comment.char = "")
  colnames(df_in) <- header_raw
  df_out <- read.csv(filename_out, as.is = TRUE, strip.white = TRUE)
  df_out <- df_out[duplicated(df_out$id) == FALSE, ]
  df_out$id <- as.integer(df_out$id)
  
  if(nrow(df_in) > nrow(df_out)){
    print(paste(i, "th file missing rows.", sep = ""))
    this_missing <- anti_join(df_in, df_out, by = c("Name" = "name", "Release.Name" = "version", "X" = "id"))
    missing <- rbind(missing, this_missing)
  } 
  if(nrow(df_in) < nrow(df_out)){
    print(paste(i, "th file has extra rows.", sep = ""))
  }
  
  combined <- left_join(df_in, df_out, by = c("Name" = "name", "Release.Name" = "version", "X" = "id"))
  if (i == 1){
    res <- combined
  }else{
    res <- rbind(res, combined)
  }  
}
rm(df_in, df_out, combined, this_missing)
# res <- filter(res, duplicated(res$X) ==FALSE)
# res_combined <- left_join(raw, res, by = c("Name" = "Name", "Release.Name" = "Release.Name"))

version_uses_latest <- res$Release.Name == "latest"
if(any(version_uses_latest)){
  print("version using lastest as tag")
  res <- res[!version_uses_latest,]
}
any(is.na(res$Rank))
any(is.na(res$Name))
any(is.na(res$Release.Name))
any(is.na(res$Release.Time))
any(is.na(res$is_ok))
table(res$is_ok, useNA = "ifany")
table(res$num_vuln[res$is_ok %in% c("True", "False")== FALSE])
table(res$critical[res$is_ok %in% c("True", "False")== FALSE])

filename_res <- paste(dir_out, "/", rawfile_name, "_vuln",".csv", sep = "")
write.csv(res, file = filename_res, quote = FALSE, row.names = FALSE)

err_data <- filter(res, res$is_ok %in% c("True", "False")== FALSE)
unique(err_data$is_ok)
unique(err_data$num_vuln)
err_data_timeout <- filter(err_data, err_data$num_vuln == "read ETIMEDOUT")

filename_err <-  paste(dir_out, "/", rawfile_name, "_vuln_err",".csv", sep = "")
write.csv(err_data, file = filename_err, quote = FALSE, row.names = FALSE)

## add hand-fix data
filename_errfix = paste(dir_out, "/", "top_2000_package_release_vuln_err-handfix.csv", sep = "")
err_fix <- read.csv(filename_errfix, header = TRUE, as.is = TRUE, 
                  strip.white = TRUE, comment.char = "")
table(err_fix$is_ok, useNA = "ifany")

res <- res[res$is_ok %in% c("True", "False")== TRUE,]
res <- rbind(res, err_fix)
res <- res[order(res$X),]

## validate
ok_data <- res[res$is_ok %in% c("True", "False"), ]
table(ok_data$is_ok, useNA = 'ifany')

vuln_data <- ok_data[ok_data$is_ok == "False", ]
table(vuln_data$num_vuln, useNA = 'ifany')
any(as.numeric(vuln_data$num_vuln) != (as.numeric(vuln_data$critical) + as.numeric(vuln_data$high) + 
                                         as.numeric(vuln_data$medium) + as.numeric(vuln_data$low) ))

novuln_data <- ok_data[ok_data$is_ok == "True", ]
table(novuln_data$num_vuln)

## tidy-up
table(res$is_ok, useNA = "ifany")
res$is_ok[res$is_ok=="TRUE"] <- "True"
res$is_ok[res$is_ok=="FALSE"] <- "False"
table(res$is_ok, useNA = "ifany")

filename_res <- paste(rawfile_name, "_vulnCount",".csv", sep = "")
write.csv(res, file = filename_res, quote = FALSE, row.names = FALSE)
