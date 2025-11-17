#!/bin/bash

# Create's a local venv
python3 -m venv inaben
# Activate venv (optimize to detect shell)
if ["echo $SHELL" = "/usr/bin/fish"] ; then 
	source inaben/bin/activate.fish
elif [ "echo$SHELL" = "/usr/bin/bash" ]; then
  source inaben/bin/activate
elif [ "echo $SHELL" = "/usr/bin/zsh" ]; then
  source inaben/bin/activate
else
  echo "Unsupported shell: $SHELL"
fi

# install dependencies used in development of this project
pip install briefcase