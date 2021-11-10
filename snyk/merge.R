# set wd etc.
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
library(dplyr)

rawfile_name = "github_releases"
total_subfiles = 9
# rawfile_name = "top2kStars_from_top5kPR_releases_new"
# total_subfiles = 8

dir_in = "./split"
dir_out = "./output"

raw <- read.csv(paste(rawfile_name, ".csv", sep = ""))
header_raw <- colnames(raw)


res = NULL
for (i in 1: total_subfiles){
  filename_in = paste(dir_in, "/", rawfile_name, "_", i, ".csv", sep = "")
  filename_out = paste(dir_out, "/", rawfile_name, "_", i,".csv", sep = "")
  df_in <- read.csv(filename_in, header = FALSE, as.is = TRUE, 
                    strip.white = TRUE, comment.char = "")
  colnames(df_in) <- header_raw
  df_out <- read.csv(filename_out,as.is = TRUE, strip.white = TRUE)
  df_out <- filter(df_out, duplicated(df_out$id) ==FALSE)
  
  if(nrow(df_in) > nrow(df_out)){
    print(paste(i, "th file missing rows.", sep = ""))
    missing <- anti_join(df_in, df_out, by = c("Name" = "name", "Release.Name" = "version"))
    
  }
  
  combined <- left_join(df_in, df_out, by = c("Name" = "name", "Release.Name" = "version"))
  if (i == 1){
    res <- combined
  }else{
    res <- bind_rows(res, combined)
  }  
}

# res <- filter(res, duplicated(res$X) ==FALSE)
# res_combined <- left_join(raw, res, by = c("Name" = "Name", "Release.Name" = "Release.Name"))



filename_res <- paste(dir_out, "/", rawfile_name, "_vuln",".csv", sep = "")
write.csv(res, file = filename_res, quote = FALSE, row.names = FALSE)

err_data <- filter(res, res$is_ok %in% c("True", "False")== FALSE)
unique(err_data$is_ok)
unique(err_data$num_vuln)
err_data_timeout <- filter(err_data, err_data$num_vuln == "read ETIMEDOUT")

filename_err <-  paste(dir_out, "/", rawfile_name, "_vuln_err",".csv", sep = "")
write.csv(err_data, file = filename_err, quote = FALSE, row.names = FALSE)

