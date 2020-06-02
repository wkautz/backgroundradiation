# backgroundradiation

# Figure Reproduction (and ideas)

### Scanner Usage

Figure out how to classify whether a scan comes from ZMap or Masscan, and see how these are used on each size of scan. To do this we will need to be able to classify scan size and identify the specific scans (The paper goes into how to use identification field to identify each scan).

Figure 3

### Country of Origin and Protocol

Once we identify a scan, we need to cross-reference sourceIP with country of origin to figure out which countries are doing which size of scans. Then we also need to look at source port and find the commonly targeted ports for each size. Both of these rely on classifying scans and scan sizes.

Figure 1, 2, (4), 7

Table 1, 2, 3, 4

### Scan Adaptation to Novel Vulnerabilities

This could be difficult with our data set. We only have data for a single day, so it is unlikely that we can see any sort of change when a vulnerability is discovered.

Figure 9

### Detecting Blocked Traffic

If we decide that we do not have enough data from the above figures, we can run some ZMap scans and try to identify destinations that block scans. This probably isn't a super good use of our time. Much of the data in this section for Zakir was people requesting to not be a part of Michigan's scans. Not something we can replicate.

Figure 10, 11, 12
Table 7
