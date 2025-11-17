#!/bin/bash

# CMS - Git Auto Publisher
# Author: Mahdi
# Purpose: Automatically add, commit, and push blog changes.

# Go to the script’s directory (so it works anywhere)
cd "$(dirname "$0")" || exit

# Get current date and time
timestamp=$(date +"%Y-%m-%d %H:%M:%S")

# Check for custom commit message
if [ -z "$1" ]; then
    commit_msg="Update ($timestamp)"
else
    commit_msg="$1"
fi

echo "🔁 Adding all changes..."
git add .

echo "📝 Committing with message: \"$commit_msg\""
git commit -m "$commit_msg"

echo "☁️ Pushing to remote..."
git push

echo "✅ Done at $timestamp"

