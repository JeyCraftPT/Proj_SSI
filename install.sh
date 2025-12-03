#!/bin/bash

cd rightHereWaiting

# Create a local venv
python3 -m venv rightHereWaiting

# Detect shell and activate venv
case "$SHELL" in
*/fish)
  source rightHereWaiting/rightHereWaiting/bin/activate
  ;;
*/bash)
  source rightHereWaiting/rightHereWaiting/bin/activate
  ;;
*/zsh)
  source rightHereWaiting/rightHereWaiting/bin/activate
  ;;
*)
  echo "Unsupported shell: $SHELL"
  exit 1
  ;;
esac

# install dependencies used in development of this project
pip install briefcase
