---
layout: page
title: stats
description: Notes on statistics, machine learning, data science
permalink: /stats/
---

Here are some of my notes on statistics, machine learning, data science.

Some of the things I’m planning to look deeper into are explainable AI, outlier and anomaly detection (time series and tabular), and analyzing graph structures. Hopefully, I can learn enough to write posts on these topics.

If you want to see a directory of all posts go <a class="page-link" href="/posts">here</a>.


<hr/>
<br/>

<ul class="post-list">
{% for post in site.categories.stats %}  <li>
    {% assign date_format = site.minima.date_format | default: "%b %-d, %Y" %}
    <span class="post-meta">{{ post.date | date: date_format }} &verbar; {{ post.sub_categories | join: ', ' | escape | upcase }}</span>

    <h3><a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a></h3>
    <p style="color:#828282">{{ post.description }}</p>
    <meta name="description" content="{{ post.summary | escape }}">
        <meta name="keywords" content="{{ post.tags | join: ', ' | escape }}"/>
  </li>
{% endfor %}
</ul>
