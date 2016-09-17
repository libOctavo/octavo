#!/bin/bash

set -o errexit -o nounset

if [ "$TRAVIS_BRANCH" != "master" ] || [ "$TRAVIS_PULL_REQUEST" != false ]
then
  echo "This commit was made against the $TRAVIS_BRANCH and not the master! No deploy!"
  exit 0
fi

rev=$(git rev-parse --short HEAD)

cd target/doc

git init
git config user.name "Łukasz Niemier"
git config user.email "lukasz@niemier.pl"

git remote add upstream "https://$GH_TOKEN@github.com/libOctavo/octavo.git"
git fetch upstream
git reset upstream/gh-pages

touch .

git add -A .
git commit -m "Documentation for ${rev}"
git push -q upstream HEAD:gh-pages
