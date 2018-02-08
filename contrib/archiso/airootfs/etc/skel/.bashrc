#!/bin/bash

# Create testnet directory
if [[ ! -L /tmp/kovri ]]; then
  ln -sf /usr/src/kovri /tmp/kovri
fi
