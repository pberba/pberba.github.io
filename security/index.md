---
layout: page
title: security
description: Notes on security, network monitoring, and SOC
permalink: /security/
---

<hr/>
<br/>

<h2> Collections </h2>

<h3> Hunting for Persistence in Linux</h3>

<ul>
{% assign sortedposts = site.categories.security | sort: 'title' %}

{% for post in sortedposts %}  
    {% if  post.sub_categories contains 'persistence' %}
        <li>
            <a href="{{ post.url }}" title="{{ post.title | escape }}">{{ post.title }}</a>
        </li>
    {% endif %}
{% endfor %}
</ul>

<h3> Data Analysis for Cyber Security 101 </h3>

<ul>
{% for post in site.categories.security %}  
	{% if  post.sub_categories contains 'security-101' %}
        <li>
            <a href="{{ post.url }}" title="{{ post.title | escape }}">{{ post.title }}</a>
        </li>
    {% endif %}
{% endfor %}
</ul>

<hr/>

<h2> Blog Posts </h2>

<ul class="post-list">
{% for post in site.categories.security %}  <li>
    {% assign date_format = site.minima.date_format | default: "%b %-d, %Y" %}
    <span class="post-meta">{{ post.date | date: date_format }} &verbar; {{ post.sub_categories | join: ', ' | escape | upcase }}</span>

    <h3><a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a></h3>
    <p style="color:#828282">{{ post.description }}</p>
    <meta name="description" content="{{ post.summary | escape }}">
        <meta name="keywords" content="{{ post.tags | join: ', ' | escape }}"/>

  </li>
{% endfor %}
</ul>
