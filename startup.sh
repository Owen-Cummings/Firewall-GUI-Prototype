#!/bin/bash

if [ -x "$(command -v docker)" ]; then {
    echo "Docker installed..."
    echo "Building container"
    docker build -t fru .
    echo "Build complete: running"
    docker run -it --rm --cap-add=NET_ADMIN -p 8000:8000 --name fru fru
    echo "Complete!"
  } 
else
    echo "Please ensure you have Docker installed!"
fi
