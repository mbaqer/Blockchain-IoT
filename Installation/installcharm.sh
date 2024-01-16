#! /bin/bash

sudo apt-get update
sudo apt-get upgrade
sudo apt-get install subversion
sudo apt-get install build-essential
sudo apt-get install m4
sudo apt-get install python3-setuptools python-dev
sudo apt-get install libgmp-dev
sudo apt-get install -y install flex bison
sudo apt-get install flex
sudo apt-get install bison
sudo apt-get install libssl-dev
sudo apt-get install git
sudo apt-get -y install python3-pip
sudo apt-get install make

sudo apt-get install -y libgmp10 libgmp-dev
sudo apt-get install -y openssl

git clone https://github.com/JHUISI/charm
cd charm
pip3 install -r requirements.txt

./configure.sh
cd ./deps/pbc && make && sudo ldconfig && cd -
make
make install && sudo ldconfig
