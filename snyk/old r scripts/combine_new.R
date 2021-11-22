#### Set wd etc. ####
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
library(dplyr)
library(ggplot2)
library(reshape2)

#### Input setup ####
filename_old_vuln <- "github_releases_vuln.csv"
filename_new_vuln <- "top2kStars_from_top5kPR_releases_new_vuln.csv"
filename_new2_vuln <- "missing_github_releases_vuln.csv"

filename_ori <- "top2kStars_from_top5kPR_releases.csv"
filename_ori_rank <- "stars_from_top5k_PageRank.csv"

dir_ori <- "./"
dir_vuln <- "./output"

#### Reading primary data ####

### raw/original data (package matadata)
ori <- read.csv(paste(dir_ori, filename_ori, sep = "/"),
                header = TRUE, as.is = TRUE, 
                strip.white = TRUE, comment.char = "")

ori_rank <- read.csv(paste(dir_ori, filename_ori_rank, sep = "/"),
                header = TRUE, as.is = TRUE, 
                strip.white = TRUE, comment.char = "")
ori_rank <- ori_rank[1:2000,]
colnames(ori_rank)[1] <- "Rank"
ori_rank$Rank <- 1:2000
any(duplicated(ori_rank$Name) == TRUE)
ori_rank$Name[ori_rank$Repository.URL == "https://github.com/nodejs/nan"] <- "nan"
# write.csv(ori_rank, 'top_2000_package_list.csv',quote = FALSE, row.names = TRUE)

#### vulnerability data
# github_releases_vuln.csv
vuln_old <- read.csv(paste(dir_vuln, filename_old_vuln, sep = "/"),
                     header = TRUE, as.is = TRUE, 
                     strip.white = TRUE, comment.char = "")
vuln_old <- subset(vuln_old, select = -c(X, id))

# top2kStars_from_top5kPR_releases_new_vuln.csv
vuln_new <- read.csv(paste(dir_vuln, filename_new_vuln, sep = "/"),
                     header = TRUE, as.is = TRUE, 
                     strip.white = TRUE, comment.char = "")
vuln_new <- subset(vuln_new, select = -c(X.1, X, id))
vuln_new <- vuln_new[, colnames(vuln_old)]
vuln_new$is_ok[!is.na(vuln_new$critical) & vuln_new$critical == 'True'] <- 'True'
vuln_new$critical[!is.na(vuln_new$critical) & vuln_new$critical == 'True'] <- NA
table(vuln_new$critical, useNA = "ifany")
vuln_new$critical <- as.integer(vuln_new$critical)


# missing_github_releases_vuln.csv
vuln_new2 <- read.csv(paste(dir_vuln, filename_new2_vuln, sep = "/"),
                     header = TRUE, as.is = TRUE,
                     strip.white = TRUE, comment.char = "")
vuln_new2 <- subset(vuln_new2, select = -c(X, id))
vuln_new2$critical[vuln_new2$critical == "to enable please contact snyk support"] <- NA
table(vuln_new2$critical, useNA = "ifany")
vuln_new2$critical <- as.integer(vuln_new2$critical)

vuln_combined <- bind_rows(vuln_new, vuln_old, vuln_new2)
length(table(vuln_combined$Name))
vuln_combined <- vuln_combined[!is.na(vuln_combined$Name),]

rm(vuln_old, vuln_new, vuln_new2)

#### Combine Vulnerability Data w/ Rank ####
res <- NULL
no_vuln <- NULL
for (i in 1: nrow(ori_rank)){
  this_package <- ori_rank$Name[i]
  this_repo <- ori_rank$Repository.URL[i]
  this_language <- ori_rank$Language[i]
  
  if( !this_package %in% vuln_combined$Name ){
    print( paste(this_package, "-", i ,"not in vuln_combined"))
    
    if (this_repo %in% vuln_combined$Repository.URL){
      print( paste("But found", this_package, "by github repo url") )
      this_vuln_df <- vuln_combined[vuln_combined$Repository.URL == this_repo,]
      this_vuln_df <- cbind(Language = this_language, this_vuln_df)
      this_vuln_df <- cbind(Rank = i, this_vuln_df)
    }else{
      no_vuln <- rbind(no_vuln, ori_rank[i,])
      this_vuln_df <- c(i, this_language, this_package, this_repo, NA, NA, 'error', 'no releases', NA, NA, NA, NA)
      # next() 
    }
  }else{
    this_vuln_df <- vuln_combined[vuln_combined$Name == this_package,]
    this_vuln_df <- cbind(Language = this_language, this_vuln_df)
    this_vuln_df <- cbind(Rank = i, this_vuln_df)
  }
  
  res <- rbind(res, this_vuln_df)  
}
rm(i, this_package, this_repo, this_vuln_df, this_language)

# write.csv(no_vuln, "more_missing_packages.csv", quote = FALSE, row.names = FALSE)

any(is.na(res$Name))
any(is.na(res$Release.Name))

table(res$is_ok, useNA = "ifany")
res_error <- res[res$is_ok == "error", ]
# write.csv(res_error, "vuln_combined_err.csv", quote = FALSE, row.names = FALSE)
# write.csv(res, "vuln_combined.csv", quote = FALSE, row.names = FALSE)
length(unique(res_error$Name))
res_error_list <- subset(res_error, duplicated(res_error$Name) == FALSE)
res_error_list <- subset(res_error_list, select = c(Rank, Language, Name))
any(is.na(res_error_list$Name))
write.csv(res_error_list, "patch_package_list.
          csv", quote = FALSE, row.names = FALSE)
