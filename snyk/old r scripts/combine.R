# set wd etc.
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
library(dplyr)
library(ggplot2)
library(reshape2)

filename_old_vuln <- "github_releases_vuln.csv"

filename_new_vuln <- "top2kStars_from_top5kPR_releases_new_vuln.csv"
filename_ori <- "top2kStars_from_top5kPR_releases.csv"

dir_ori <- "./"
dir_vuln <- "./output"

ori <- read.csv(paste(dir_ori, filename_ori, sep = "/"),
                header = TRUE, as.is = TRUE, 
                strip.white = TRUE, comment.char = "")

vuln_old <- read.csv(paste(dir_vuln, filename_old_vuln, sep = "/"),
                    header = TRUE, as.is = TRUE, 
                    strip.white = TRUE, comment.char = "")

vuln_new <- read.csv(paste(dir_vuln, filename_new_vuln, sep = "/"),
                     header = TRUE, as.is = TRUE, 
                     strip.white = TRUE, comment.char = "")
vuln_new <- subset(vuln_new, select = -X.1)
vuln_new <- vuln_new[, colnames(vuln_old)]
vuln_new$id <- as.integer(vuln_new$id)
vuln_new$critical <- as.integer(vuln_new$critical)
vuln_combined <- bind_rows(vuln_new, vuln_old)

res <- left_join(ori, vuln_combined, by = c( "Name" = "Name", "Release.Name" = "Release.Name",
                                       "Repository.URL" = "Repository.URL", "Release.URL" = "Release.URL"))
res <- subset(res, select = -c(X.x, X.y, id))

### hand-fix is_ok == NA
count(res, is_ok)
na_rows <- res[is.na(res$is_ok),]
res$is_ok[res$Release.URL == na_rows$Release.URL] <- "True"
res$num_vuln[res$Release.URL == na_rows$Release.URL] <- ""
###

write.csv(res, file = "top2kStars_from_top5kPR_releases_vuln.csv", quote = FALSE, row.names = FALSE)

err_data <- filter(res, res$is_ok %in% c("True", "False")== FALSE)
count(err_data, err_data$is_ok)
count(err_data, err_data$num_vuln)
write.csv(err_data, file = "top2kStars_from_top5kPR_releases_vuln_err.csv", quote = FALSE, row.names = FALSE)


### Preliminary Stats
count(res, res$is_ok)
count(res, res$num_vuln)

ori_rank <- read.csv("stars_from_top5k_PageRank.csv", header = TRUE, as.is = TRUE, 
                     strip.white = TRUE, comment.char = "")
ori_rank <- ori_rank[1:2000,]
ori_rank$In.Release.Csv <- ori_rank$Name %in% res$Name
ori_rank$In.Vuln.Combined <- ori_rank$Repository %in% vuln_combined$Repository.URL
ori_rank$Can.Fix <- ori_rank$In.Release.Csv == FALSE && ori_rank$In.Vuln.Combined == TRUE

missing_release <- ori_rank[ori_rank$In.Release.Csv == FALSE,]
missing_release <- subset(missing_release, select = -c(In.Release.Csv, In.Vuln.Combined, Can.Fix))
write.csv(missing_release, file = "447_missing_package.csv", quote = FALSE, row.names = FALSE )

###
res_latest <- res[duplicated(res$Name)==FALSE, ]
res_latest$rank <- 1:nrow(res_latest)
count(res_latest, res_latest$is_ok)
count_latest <- count(res_latest, res_latest$is_ok)
count_latest$percentage <- count_latest$n/sum(count_latest$n)

count_latest$ymax = cumsum(count_latest$percentage)
count_latest$ymin = c(0, head(count_latest$ymax, n=-1))
count_latest$labelPosition <- (count_latest$ymax + count_latest$ymin) / 2
count_latest$catagory <-c("No data", "Has vulnerabilites", "No vulnerabilities")
count_latest$color <- c("darkgrey", "brown2", "darkolivegreen1")
count_latest$label <- paste0(count_latest$catagory, "\n count: ", count_latest$n)
p <- ggplot(count_latest, aes(ymax=ymax, ymin=ymin,xmax=4, xmin=3, fill=catagory)) +
  geom_rect(fill=count_latest$color ) +
  geom_text( x=2, aes(y=labelPosition, label=label, color=color), size=6) +
  coord_polar(theta="y") + # Try to remove that to understand how the chart is built initially
  xlim(c(-1, 4)) + # Try to remove that to see how to make a pie chart
  theme_void() +
  theme(legend.position = "right")
p

#### res_latest_vuln ####
res_latest_vuln <- res_latest[res_latest$is_ok == "False", ]
res_latest_vuln$num_vuln <- as.numeric(res_latest_vuln$num_vuln)
res_latest_vuln_long <- melt(subset(res_latest_vuln, select = c(critical, high, medium, low, rank)) ,  
                             id.vars = 'rank', variable.name = 'severity')

library(viridis)
library(hrbrthemes)
p <- ggplot(res_latest_vuln_long, aes(x = rank, y = value,  color = severity)) + 
  geom_bar(position="dodge", stat="identity")+
  scale_fill_viridis(discrete = T, option = "E") +
  facet_wrap(~severity, scales = "free") +
  theme(legend.position="none") +
  xlab("Package Rank") +
  ylab("Vulnerability Count")
p

# p <- ggplot(res_latest_vuln_long, aes(x=severity, y=value)) + 
#   geom_boxplot(fill="slateblue", alpha=0.2) + 
#   xlab("cyl")
# p
# 
# library(ggridges)
# p <- ggplot(res_latest_vuln_long, aes(x = rank, y = value, fill = severity)) +
#   geom_density_ridges() +
#   theme_ridges() + 
#   theme(legend.position = "bottom")
# p


### package history ###
res_had_vuln <- NULL

for (rank in 1: nrow(res_latest)){
  this_package <- res_latest$Name[rank]
  this_subset <- res[res$Name==this_package, ]
  
  if(any(is.na(this_subset$is_ok)) || any(this_subset$is_ok == "error") ){
    next()
  }
  
  if(any(this_subset$is_ok == "False")){
    this_subset$rank <- rep(rank, nrow(this_subset))
    if (!is.null(res_had_vuln)){
      res_had_vuln <- bind_rows(res_had_vuln, this_subset)
    }else{
      res_had_vuln <- this_subset
    }
  }
}
rm(this_package, this_subset)
length(unique(res_had_vuln$Name))

res_had_vuln$is_ok <- as.logical(res_had_vuln$is_ok)
res_had_vuln$has_vuln <- !res_had_vuln$is_ok
res_had_vuln_mean <- aggregate(res_had_vuln$has_vuln, list(res_had_vuln$Name, res_had_vuln$rank), mean)
colnames(res_had_vuln_mean) <- c("Name", "rank", "mean")
res_had_vuln_mean$percentage <- floor(res_had_vuln_mean$mean*100)

p <- ggplot(res_had_vuln_mean, aes(x=percentage )) +
  geom_histogram(binwidth=5, fill="#69b3a2", color="#e9ecef", alpha=0.9) + 
  ggtitle("Bin size = 5%") +
  ylab("Package Count") +
  xlab("Versions with Vulnerabilities (%)") + 
  ggtitle("Percentage of Versions with Vulnerabilities")
p

res_had_vuln_total <- aggregate(res_had_vuln$has_vuln,  by = list(res_had_vuln$Name, res_had_vuln$rank), FUN = function(x) length(x)   )
colnames(res_had_vuln_total) <- c("Name", "rank", "total")
res_had_vuln_sum <- aggregate(res_had_vuln$has_vuln,  by = list(res_had_vuln$Name, res_had_vuln$rank), FUN = function(x) sum(x) )
colnames(res_had_vuln_sum) <- c("Name", "rank", "sum")

res_had_vuln_summary <- merge(res_had_vuln_total, res_had_vuln_sum, by = c("Name", "rank") )
p <- ggplot(res_had_vuln_summary, aes(x=total, y=sum)) + 
  geom_point() +
  geom_rug(col="steelblue",alpha=0.1, size=1.5) + 
  scale_x_continuous(limits = c(0, 30))
p
