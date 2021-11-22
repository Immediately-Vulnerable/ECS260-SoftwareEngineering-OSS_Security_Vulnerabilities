# set wd etc.
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
library(dplyr)

rawfile_name = "top_2000_package_release_vulnCount_had_vuln"
total_subfiles = 12


dir_in = "./split"
dir_out = "./output"

raw <- read.csv(paste(rawfile_name, ".csv", sep = ""))
header_raw <- colnames(raw)


res <- NULL
missing <- NULL
for (i in 1: total_subfiles){
  filename_in = paste(dir_in, "/", rawfile_name, "_", i, ".csv", sep = "")
  filename_out = paste(dir_out, "/", rawfile_name, "_", i,".tsv", sep = "")
  df_in <- read.csv(filename_in, header = FALSE, as.is = TRUE, 
                    strip.white = TRUE, comment.char = "")
  colnames(df_in) <- header_raw
  df_out <- read.table(filename_out, as.is = TRUE, strip.white = TRUE, sep = "\t", header = TRUE, fill = TRUE)
  df_out$id <- as.integer(df_out$id)
  # 
  # if( nrow(df_in) > length(unique(df_out$name)) ){
  #   print(paste(i, "th file missing rows.", sep = ""))
  #   this_missing <- anti_join(df_in, df_out, by = c("Name" = "name", "Release.Name" = "version", "X" = "id"))
  #   missing <- rbind(missing, this_missing)
  # } 
  # if(nrow(df_in) < length(unique(df_out$name)) ){
  #   print(paste(i, "th file has extra rows.", sep = ""))
  # }
  # 
  combined <- right_join(df_in, df_out, by = c("Name" = "name", "Release.Name" = "version", "X" = "id"))
  if (i == 1){
    res <- combined
  }else{
    res <- rbind(res, combined)
  }  
}
rm(df_in, df_out, combined, this_missing)

res <- subset(res, select = -c(num_vuln, critical, high, medium, low))

table(res$is_ok.x)
table(res$is_ok.y)
any(res$is_ok.y == "True")
table(res$is_ok.y[res$is_ok.y %in% c("True", "False") == FALSE])

#### write error data ####
err_data <- filter(res, res$is_ok.y %in% c("True", "False")== FALSE)
unique(err_data$is_ok.y)
unique(err_data$vulnIndex)

filename_err <-  paste(dir_out, "/", rawfile_name, "_err",".csv", sep = "")
write.csv(err_data, file = filename_err, quote = FALSE, row.names = FALSE)

#### get rid of error data from res and fill in the patched data ####
filename_patch = paste(dir_out, "/", rawfile_name, "_err_fixed",  ".tsv", sep = "")
res_patch <- read.table(filename_patch, as.is = TRUE, strip.white = TRUE, sep = "\t", header = TRUE, fill = TRUE)
res_patch <- full_join(err_data[, 1:6], res_patch, by = c("Name" = "name", "Release.Name" = "version", "X" = "id"))

res_good <- res[res$is_ok.y %in% c("True", "False")== TRUE, ]
res_good <- subset(res_good, select = -c(is_ok.x))
colnames(res_good)[colnames(res_good) == "is_ok.y"] <- "is_ok"

res_final <- bind_rows(res_good, res_patch)
res_final <- res_final[order(res_final$X, res_final$vulnIndex), ]
any(is.na(res_final))

filename_res <- paste(rawfile_name, "_vulnDetails",".tsv", sep = "")
write.table(res_final, file = filename_res, quote = FALSE, row.names = FALSE, sep = "\t")
