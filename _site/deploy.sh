#!/bin/bash
bundle exec jekyll clean
JEKYLL_ENV=production bundle exec jekyll build
rm -rf docs
cp -a _site/. docs/
touch docs/.nojekyll
echo "faultpoint.com" > docs/CNAME
git add -A
git commit -m "Publish static site to /docs"
git push
