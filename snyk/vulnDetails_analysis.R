#### Set wd etc. ####
setwd("/Users/Nan/projects/ECS260/snyk/data/npm/")
rm(list = ls())
library(dplyr)
library(ggplot2)
library(reshape2)
library(viridis)
library(tidyverse)
library(ggridges)

#### Input setup ####
filename_vulnDetails <- "top_2000_package_release_vulnCount_had_vuln_vulnDetails.tsv"
vulnDetails <- read.table(filename_vulnDetails,
                      header = TRUE, as.is = TRUE, sep = "\t",
                      strip.white = TRUE, comment.char = "")
any(is.na(vulnDetails$Name))
any(is.na(vulnDetails$Release.Name))
any(is.na(vulnDetails$Release.Time))
table(vulnDetails$is_ok, useNA = "ifany")
length(unique(vulnDetails$Name))
length(unique(vulnDetails$X))


filename_vulnCount <- "top_2000_package_release_vulnCount.csv"
vulnCount <- read.csv(filename_vulnCount,
                      header = TRUE, as.is = TRUE, 
                      strip.white = TRUE, comment.char = "")
any(is.na(vulnCount$Name))
any(is.na(vulnCount$Release.Name))
any(is.na(vulnCount$Release.Time))
table(vulnCount$is_ok, useNA = "ifany")


#### Vuln Details: is direct  ####
vulnDetails$isDirectDepency <- vulnDetails$pathDepth < 2
table(vulnDetails$pathDepth)
print( paste("self:",  signif( sum(vulnDetails$pathDepth == 1) / length(vulnDetails$pathDepth) * 100, digits = 3), "%") )
print( paste("direct:",  signif( sum(vulnDetails$pathDepth == 2) / length(vulnDetails$pathDepth) * 100, digits = 3), "%") )
print( paste("indirect:",  signif( sum(vulnDetails$pathDepth > 2) / length(vulnDetails$pathDepth) * 100, digits = 3), "%") )

## depth vs. severity
p <- ggplot(vulnDetails,  aes(x = severity, y = pathDepth , fill = severity)) + 
  geom_boxplot()+
  # scale_fill_viridis(discrete = TRUE, alpha=0.1) +
  # geom_jitter(color="black", size=0.4, alpha=0.1) +
  ggtitle("Vulnerable path depth based on severity", ) +
  ylab("Vulnerble Path Depth")
p
ggsave(filename = "PathDepth_Severity_AllRelease.png", plot = p)



#### Vuln Details: vulnTimeLapse = (PublicationTime - ReleaseTime )  ####
## Note: >0: immediate vuln; <0 vuln discovered after release; unit: days
vulnDetails$publicationTime <- parse_datetime(vulnDetails$publicationTime)
vulnDetails$Release.Time <- parse_datetime(vulnDetails$Release.Time)
vulnDetails$VulnTimeLapse <- as.numeric( difftime(vulnDetails$publicationTime, vulnDetails$Release.Time, units = "days") )

print( paste("immediate vul:", sum(vulnDetails$VulnTimeLapse < 0) ) )
print( paste("immediate vul:",  signif( sum(vulnDetails$VulnTimeLapse < 0 ) / length(vulnDetails$VulnTimeLapse) * 100, digits = 6), "%") )

## (PublicationTime - ReleaseTime) vs. severity
p <- ggplot(vulnDetails,  aes(x = severity, y = VulnTimeLapse , fill = severity)) + 
  geom_boxplot(outlier.size = 0.3)+
  ggtitle("Time lapsed between Vulnerable Publication Time \n and Package Release Time", ) +
  ylab("Time lapsed (Days)") +
  geom_hline(yintercept = 0, color = "#eecd60") +
  annotate("segment", x = 4.3, xend = 4.3, y = 0, yend = -2000, colour = "#ab0000", size=0.7, alpha=1, arrow=arrow() ) + 
  annotate("segment", x = 4.45, xend = 4.45, y = 0, yend = 2000, colour = "#5f9747", size=0.7, alpha=1, arrow=arrow() ) +
  annotate("text", x = 4.3, y = -2350, label = "Immediate \n vulnerable",  colour = "#ab0000", size = 3) + 
  annotate("text", x = 4.3, y = 2900, label = "Vulnerable \n discovered \n after \n release",  colour = "#5f9747", size = 3) 
p
ggsave(filename = "TimeLapsed_Severity_AllRelease.png", plot = p)

# p <-  ggplot( vulnDetails, aes(x = VulnTimeLapse, fill = severity)) +
#   geom_histogram( color="#e9ecef", alpha=0.6, position = 'identity') +
#   labs(fill="") +
#   facet_wrap(~severity, scales = "free")
# 
# p

#### Vuln Details: vuln title #####
vulnType <- data.frame(unclass(table(vulnDetails$title)))
colnames(vulnType) <- "count"
vulnType$perc <- format( signif(vulnType$count / nrow(vulnDetails)*100, digits = 3), scientific = F)

top_vuln_types <- c("Regular Expression Denial of Service (ReDoS)", "Prototype Pollution", "Arbitrary Code Injection")
vulnDetails_topType <- vulnDetails[vulnDetails$title %in% top_vuln_types,]
table(vulnDetails_topType$title)

ggplot(vulnDetails_topType, aes(x = VulnTimeLapse, y = title, fill = title)) +
  stat_density_ridges(scale = 0.9, quantile_lines = TRUE) +
  theme_ridges() +
  ggtitle("Time lapsed between Vulnerable Publication Time \nand Package Release Time: \nTop 3 vulnerable types", ) +
  theme(legend.position = "none") + 
  geom_vline(xintercept = 0, color = "#eecd60") +
  ylab("")+
  xlab("Time lapsed (Days)") +
  annotate("segment", x = 0, xend = -1000, y = 0.5, yend = 0.5, colour = "#ab0000", size=0.7, alpha=1, arrow=arrow() ) +
  annotate("segment", x = 0, xend = 4000, y = 0.5, yend = 0.5, colour = "#5f9747", size=0.7, alpha=1, arrow=arrow() ) +
  annotate("text", x = -1000, y = 0.5, label = "Immediate \n vulnerable",  colour = "#ab0000", size = 5) + 
  annotate("text", x = 1500, y = 0.5, label = "Vulnerable discovered \n after release",  colour = "#5f9747", size = 5) 
# 
# ggplot( vulnDetails_topType, aes(x=VulnTimeLapse, fill=title)) +
#   geom_histogram( alpha=0.6) +
#   labs(fill="")+
#   facet_wrap(~title, scales = "free")
