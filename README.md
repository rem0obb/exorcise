# Exorcise: Malware Analysis Engine

![](assets/malware-analysis.gif)

This is an engine designed for analyzing malware, for clone repository `git clone --recurse-submodules git@github.com:covinhas-in/Engine-Malware.git`

## Dependencies

To install the required dependencies, use the following command:

```sh
sudo apt install libyara-dev binutils
```

Make sure you have libyara-dev version 4.1.3 or higher.
Building the Project, g++ compiler version 11.4.0

# To build the project, follow these steps:

```sh
mkdir build
cd build
cmake ..
make
```

Once you've completed these steps, your project should be ready for use.

# Help Tool

To get help with the tool, use the `-h` flag, like this: `./exorcise -h`.

```sh

  ./exorcise {OPTIONS}

    Exorcise: Malware Analysis Engine

  OPTIONS:

      Yara Options:
        -f, --folder                      Analyze as a folder of Yara rules (use
                                          with -r)
      -r[rules], --rules=[rules]        The folder or file containing Yara rules
      -p[path], --path=[path]           The path to analyze (folder or file)
      -h, --help                        Display this help menu

    The Exorcise: Malware Analysis engine is a powerful post-incident malware
    analysis tool, known for its ability to quickly scan for ransomware and
    detect over 100 distinct malware families within seconds. This cutting-edge
    tool serves as a guardian against digital threats, offering exceptional
    efficiency and accuracy in post-incident analysis.


```

# Documentation

To access the documentation, simply go to [DOCS](docs/DOCS.md)
