---
layout: page
title: security
description: Notes on security, network monitoring, and SOC
permalink: /security/
---


Notes on cyber security, network monitoring, and SOC operations from books and papers that I've read and the experience I've had working in a SOC. 

Currently I'm interested in applying data science specifically to blue team cyber security.
<hr/>
<br/>

<h2> Data Analysis for Cyber Security 101 </h2>

I'm still learning and trying to apply data science concepts in cyber security. Here are stuff that I've learned as I go.

<ul class="post-list">
{% for post in site.categories.security %}  
	{% if  post.sub_categories contains 'security-101' %}
	<li>
	
    {% assign date_format = site.minima.date_format | default: "%b %-d, %Y" %}
    <span class="post-meta">{{ post.date | date: date_format }} &verbar; {{ post.sub_categories | join: ', ' | escape | upcase }}</span>

    <h3><a href="{{ post.url | relative_url }}">{{ post.mini_title | escape }}</a></h3>
    <p style="color:#828282">{{ post.description }}</p>
    <meta name="description" content="{{ post.summary | escape }}">
        <meta name="keywords" content="{{ post.tags | join: ', ' | escape }}"/>
  </li>
      {% endif %}
{% endfor %}
</ul>

<h2> Blog Posts </h2>

<ul class="post-list">
{% for post in site.categories.security %}  <li>
	{% unless post.sub_categories contains 'security-101' %}
    {% assign date_format = site.minima.date_format | default: "%b %-d, %Y" %}
    <span class="post-meta">{{ post.date | date: date_format }} &verbar; {{ post.sub_categories | join: ', ' | escape | upcase }}</span>

    <h3><a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a></h3>
    <p style="color:#828282">{{ post.description }}</p>
    <meta name="description" content="{{ post.summary | escape }}">
        <meta name="keywords" content="{{ post.tags | join: ', ' | escape }}"/>
    {% endunless %}
  </li>
{% endfor %}
</ul>
