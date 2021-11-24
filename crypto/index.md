---
layout: page
title: crypto
description: CTF writeups and blog posts related to crypto
permalink: /crypto/
---

My write-ups are in my [ctf-solutions](https://github.com/pberba/ctf-solutions) repository, but I will try to migrate some of them here.

If you want to see a directory of all posts go <a class="page-link" href="/posts">here</a>.

<h2> Blog Posts </h2>


<ul class="post-list">
{% for post in site.categories.crypto %}  <li>
    {% assign date_format = site.minima.date_format | default: "%b %-d, %Y" %}
    <span class="post-meta">{{ post.date | date: date_format }} &verbar; {{ post.sub_categories | join: ', ' | escape | upcase }}</span>

    <h3><a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a></h3>
    <p style="color:#828282">{{ post.description }}</p>
    <meta name="description" content="{{ post.summary | escape }}">
        <meta name="keywords" content="{{ post.tags | join: ', ' | escape }}"/>
  </li>
{% endfor %}
	<li>
    <span class="post-meta"> May 25, 2020  &verbar; PHISHING, CRYPTO </span>
    <h3><a href="/security/2020/05/28/lastpass-phishing/#how-lastpass-decrypts-your-vault">How LastPass decrypts your vault</a></h3>
    <p style="color:#828282">How LastPass handles the master password and the encrypted vault. This is a segment of the longer blog post.</p>
  </li>
</ul>
