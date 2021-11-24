---
layout: post
title: A gentle introduction to HDBSCAN and density-based clustering
date: 2020-07-08
category: stats
sub_categories: [clustering, unsupervised learning, 101]
author: "Pepe Berba"
summary: Explaining density based clustering in ~5-minutes
subtitle: Explaining density based clustering in ~5-minutes
description: Explaining HDBSCAN in ~5-minutes. A beginner friendly to primer to the core ideas of density based clustering
tags: [clustering, unsupervised learning, hdbscan, density-based clustering]
header-img-direct: https://cdn-images-1.medium.com/max/800/1*CHhb45CRYl5ZJbpmP__CVQ.jpeg
---

*“Hierarchical Density-based Spatial Clustering of Applications with Noise”* (What a mouthful...), **HDBSCAN, is one of my go-to clustering algorithms. It’s a method that I feel everyone should include in their data science toolbox**
.

I’ve written about this in [my previous blog post](https://pberba.github.io/stats/2020/01/17/hdbscan/), where I try to explain HDBSCAN in as much depth as I could. This time I am taking the opposite approach: I will try to explain the main ideas HDBSCAN and density-based clustering **as succinctly as I can.**

I think (and I hope) that this primer on HDBSCAN would be friendlier for beginners and new-comers in data science


### **Why density-based clustering?**

Let’s start with a sample [data set](https://github.com/lmcinnes/hdbscan/blob/master/notebooks/clusterable_data.npy).

![](https://cdn-images-1.medium.com/max/800/1*6Plad8ULc5VoOcML5wJjdg.png)

If you visually try to identify the clusters, you might identify 6 clusters.

![6 “intuitive” clusters](https://cdn-images-1.medium.com/max/800/1*ubCZDj7CWEbGLCeqpFF43w.png)
_6 “intuitive” clusters_

Even when provided with the correct number of clusters, K-means clearly gives bad results. Some of the clusters we identified above are separated into two or more clusters. HDBSCAN, on the other hand, gives us the expected clusters.

![](https://cdn-images-1.medium.com/max/1200/1*_ttZpXcDUmaNmQYwyT2qkQ.png)

Unlike K-means, density-based methods work well even when the data isn’t clean and the clusters are weirdly shaped. 

![](https://cdn-images-1.medium.com/max/800/1*J9KUOHfsrvRA_thtrPKY-A.png)

How does HDBSCAN do this? At a high level, we can simplify the process of density-based clustering into these steps:

1.  Estimate the densities 
2.  Pick regions of high density
3.  Combine points in these selected regions

### Estimating densities 

We need some method to estimate the density around certain points. One common way to do this is by using **“core distance.”** This is the distance of a point to its K-th nearest neighbor. 

![Core distance with K=7](https://cdn-images-1.medium.com/max/800/1*XI359LqPheRAR4me3-jFtg.png)
_Core distance with K=7_

Points in denser regions would have smaller core distances while points in sparser regions would have larger core distances. **Core distance is what makes these methods “density-based”.**

![](https://cdn-images-1.medium.com/max/800/1*eRW_IFZeL1aZ8AL26BwArw.png)

Given the core distances, we can derive an estimate of the density by getting the inverse of it. With these estimates, we can get an idea of what the **density landscape** looks like.

![Estimated densities from our sample data set](https://cdn-images-1.medium.com/max/1200/1*zofmkIOPOKMB5e03p90Jvg.jpeg)
_Estimated densities from our sample data set_

If we plot these densities, we can see that the mountains of this density landscape correspond to the different clusters of the data.

### Simple Cluster Selection

One way to select clusters is to pick a global threshold. By getting the points with densities above the threshold, and grouping these points together, we get our clusters.

Think of this illustration below as a cross-section of the surface plot above.

![Two different clusterings based on different thresholds](https://cdn-images-1.medium.com/max/800/1*txhiQ6wFmrxd0MwCdwU3vQ.png)
_Two different clusterings based on different thresholds_

Imagine islands on the ocean, where the sea level is the threshold and the different islands are your clusters. The land below the sea level is noise. As the sea level goes down, new islands appear and some islands combine to form bigger islands.

Here are several clusters that result as we lower the sea level. (With K=30)

![](https://cdn-images-1.medium.com/max/800/1*xXarh-oM2hLUUrGvipvoMA.jpeg)  
<img src="https://cdn-images-1.medium.com/max/600/1*wRYKs5vLfs5C4pJOfNT7Ew.png" style="width:100%" alt>

![](https://cdn-images-1.medium.com/max/800/1*CHhb45CRYl5ZJbpmP__CVQ.jpeg) 
<img src="https://cdn-images-1.medium.com/max/600/1*U7HVWj4PRJe0c_K_wxq0UA.png" style="width:100%" alt>

![](https://cdn-images-1.medium.com/max/800/1*mPHCPke0wy6xWrqoEusknw.jpeg) 
<img src="https://cdn-images-1.medium.com/max/600/1*pyLU6QpShSpAJfTfn0Yn2A.png" style="width:100%" alt>

This approach is close to what DBSCAN does. Although simple, **this requires us to find the proper threshold to get meaningful clusters. **

If you set the threshold too high, too many points are considered noise and you have under grouping. If you set it too low, you might over group the points, and everything is just one cluster.

### Cluster Selection for varying densities

**With the global threshold method, you might have a hard time when the clusters have varying densities.** If we use just one threshold in the example below, we either over-group the blue and yellow clusters or we fail to include the entire red cluster.

![Optimal clustering requires different thresholds](https://cdn-images-1.medium.com/max/800/1*UUz0AP4zSKkUt5IVkl0WSg.png)
_Optimal clustering requires different thresholds_

You might be tempted to think that each peak in the density should be one cluster, however, this will not always be optimal. 

Look at the image below. On the left, there should be 3 clusters, and on the right, there should be 2 clusters.

![](https://cdn-images-1.medium.com/max/800/1*ZgaGZYtFrvXfXQha_y2kHg.png)

HDBSCAN first builds a hierarchy to figure out which peaks end up merging together and in what order, and then for each cluster it asks, **is it better to keep this cluster or split it up into its subclusters**? In the image above, should we pick the _blue and yellow_ regions or the _green region_ only?

Given the density landscape, you can think of each mountain is one cluster. We have to decide whether or not two peaks are part of the same mountain. _Are there two mountains, or just one mountain with two peaks? _

Below are examples that illustrate this point

![“3 cluster data set”](https://cdn-images-1.medium.com/max/800/1*2yX4kltav0rEaDyMddeEZw.jpeg)
_“3 cluster data set”_
![“2 cluster data set”](https://cdn-images-1.medium.com/max/800/1*u9OQ3z9oOxK_tnzU_jAAPQ.jpeg)
_“2 cluster data set”_

If you use the sklearn’s HDBSCAN, you can plot the cluster hierarchy.

![](https://cdn-images-1.medium.com/max/800/1*rWmux9oRT-5cPtfK6i3TNA.jpeg)

To choose, we look at which one “persists” more. Do we see the peaks more together or apart? Cluster stability (persistence) is represented by the areas of the different colored regions in the hierarchy plot. We use cluster stability to answer our mountain question.

When the two peaks are actually two mountains, the sum of the volume of the two peaks is larger than the volume of their base. When the peaks are just features of a single mountain, then the volume of the base would be larger than the sum of the peaks’ volume.

**Using this heuristic, HDBSCAN is able to decide whether or not to subdivide a cluster to its subclusters**. By doing so, it automatically chooses which clusters to extract.

### Conclusion and further resources

1.  We estimate densities based on core distances and form **the density landscape** (what makes these density-based)
2.  We can use a global threshold to **set the sea level at and identify the islands** (DBSCAN)
3.  We can try to decide, **are these several mountains or one mountain with multiple peaks**? (HDBSCAN)

I hope this gives you the gist how DBSCAN/HDBSCAN works and what makes these methods “density based”. Other methods such as OPTICS or DeBaCl use similar concepts but differ in the way they choose the regions.

If you want to know more about the statistical motivation for HDBSCAN, implementation details of how points are combined together, or how HDBSCAN builds the hierarchy you can [check out blog post](https://pberba.github.io/stats/2020/01/17/hdbscan/) where I go into much more detail.

Technical Note: The estimated densities plotted here isn’t just `1 / core_distance`. I had to apply some transformation to the data to make it more visually appealing.

<br/>
<hr/> 
<br/>


[**Understanding HDBSCAN and Density-Based Clustering** pberba.github.io](https://pberba.github.io/stats/2020/01/17/hdbscan/ "https://pberba.github.io/stats/2020/01/17/hdbscan/")[](https://pberba.github.io/stats/2020/01/17/hdbscan/)

[**How HDBSCAN Works - hdbscan 0.8.1 documentation** hdbscan.readthedocs.io](https://hdbscan.readthedocs.io/en/latest/how_hdbscan_works.html "https://hdbscan.readthedocs.io/en/latest/how_hdbscan_works.html")[](https://hdbscan.readthedocs.io/en/latest/how_hdbscan_works.html)

[**Accelerated Hierarchical Density Clustering** arxiv.org](https://arxiv.org/abs/1705.07321 "https://arxiv.org/abs/1705.07321")[](https://arxiv.org/abs/1705.07321)

<iframe width="560" height="315" src="https://www.youtube.com/embed/dGsxd67IFiU" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

[Photo by Markos Mant](https://unsplash.com/photos/sL0xKYbb04w)