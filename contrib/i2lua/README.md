i2lua is an experimental i2p router with an embedded lua interpreter for use in test networks and research.

For now, don't use this unless you know exactly what you want to do, how to do it and want to hack on the source code.

Building:

    git clone https://github.com/majestrate/kovri -b development kovir-dev
    mkdir build
    cd build
    cmake -DWITH_LUA=ON -DWITH_AESNI=ON ../kovri-dev
    make -j8

Running:

    ./i2lua example.lua
