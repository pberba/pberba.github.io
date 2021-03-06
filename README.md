# pberba.github.io

This is the source code for my [blog](pberba.github.io). It's a static
website powered by [Jekyll](https://jekyllrb.com/). 

## Dependencies

Here are the dependencies for this blog. You can also check the `Gemfile` for more
information: 

- Ruby==2.3.1
- gem==2.5.2.1
- jekyll=3.6.3
- minima==2.0
- html-proofer
- jekyll-sitemap
- jekyll-feed==0.6
- jekyll-seo-tag

## Set-up

Make sure that you have bundler in your system:

```shell
$ sudo gem install bundler
```

Then, build the dependencies and call `jekyll serve`

```shell
$ git clone https://github.com/pberba/pberba.github.io.git 
$ cd pberba.github.io/
$ bundle install
$ bundle exec jekyll serve
```

The page, by default, should be running at [localhost:4000](localhost:4000)

## Contribute

If you found some errors in spelling/grammar, mistakes in content and the like, then feel
free to fork this repository and [make a Pull Request!](https://help.github.com/articles/creating-a-pull-request/)

[![licensebuttons by](https://licensebuttons.net/l/by/3.0/88x31.png)](https://creativecommons.org/licenses/by/4.0)
