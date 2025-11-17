#!/bin/bash

# Create's a local venv
python3 -m venv inaben
# Activate venv (optimize to detect shell)
if ["echo $SHELL" = "usr/bin/fish"] ; then 
	source enaben/bin/activate.fish
elif [ "echo$SHELL" = "/bin/bash" ]; then
  source enaben/bin/activate
elif [ "echo $SHELL" = "/bin/zsh" ]; then
  source enaben/bin/activate.zsh
else
  echo "Unsupported shell: $SHELL"
fi

# install dependencies used in development of this project
pip install briefcase