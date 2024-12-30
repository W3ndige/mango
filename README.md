# Mango

Simplest YaraX scanner written in C++.

## Usage

First you need to install the YaraX C/C++ API. Follow the instructions [here](https://virustotal.github.io/yara-x/docs/api/c/c-/).

Now you will be ready compile the project. 

* Create the `build` directory - `mkdir build & cd build`
* Use Cmake to generate build files `cmake ..`
* Build the binary with `make`

To use the project you can run `mango --help`

```
YaraX scanner
Usage: ./mango [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -y,--yara TEXT REQUIRED     Path to YaraX rule.
  -t,--target TEXT REQUIRED   Path to the file to scan.
```

## Resources

* https://virustotal.github.io/yara-x/docs/api/c/c-/ 
* https://github.com/gabime/spdlog
* https://github.com/CLIUtils/CLI11
