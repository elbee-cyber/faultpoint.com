#!/bin/bash
read -p "Deploy to GitHub? (y/N) " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Aborted."
  exit 1
fi

bundle exec jekyll clean
JEKYLL_ENV=production bundle exec jekyll build --drafts
rm -rf docs
cp -a _site/. docs/
touch docs/.nojekyll
echo "faultpoint.com" > docs/CNAME
git add -A
git commit -m "Publish static site to /docs"
git push
