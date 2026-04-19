bundle exec jekyll clean
JEKYLL_ENV=production bundle exec jekyll build --drafts

# Then preview it
cd _site
python3 -m http.server 4001
