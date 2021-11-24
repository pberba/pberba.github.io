---
layout: page
title: Posts Archive
description: A list of all 
permalink: /posts/
---

Here are all the blog posts I've written so far.

<ul>
  {% for post in site.posts %}
    <li>
        <span>{{ post.date |  date: "%Y/%m/%d" }}</span> » <a href="{{ post.url }}" title="{{ post.title | escape }}">{{ post.title }}</a> ({{ post.category }})
    </li>
  {% endfor %}
</ul>
