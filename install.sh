#!/bin/bash

# Create a local venv
python3 -m venv inaben

# Detect shell and activate venv
case "$SHELL" in
*/fish)
  source inaben/bin/activate.fish
  ;;
*/bash)
  source inaben/bin/activate
  ;;
*/zsh)
  source inaben/bin/activate
  ;;
*)
  echo "Unsupported shell: $SHELL"
  exit 1
  ;;
esac

# install dependencies used in development of this project
pip install briefcase

