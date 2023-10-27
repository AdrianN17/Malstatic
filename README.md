![Version - 0.1](https://img.shields.io/badge/Version-0.1-2ea44f)
![Python - 3.7](https://img.shields.io/badge/Python-3-388E3C)
[![License - MIT](https://img.shields.io/badge/License-MIT-E64A19)](https://github.com/AdrianN17/Malstatic/blob/main/LICENSE)
[![Docker Image  - 0.1](https://img.shields.io/badge/Docker_Image_-0.1-00BCD4)](https://hub.docker.com/r/adriann17/malstatic)
![Type - Malware Analysis](https://img.shields.io/badge/Type-Malware_Analysis-D32F2F)

# Malstatic

Web tools for PE static analysis

Malstatic is a small and useful tool which can help you in you malware analysis. It's a mix of multiples tools.

* [Radare2](https://github.com/radareorg/radare2) and [r2pipe](https://pypi.org/project/r2pipe/)
* [Flare-Capa](https://github.com/mandiant/capa)
* [Flare-Floss](https://github.com/mandiant/flare-floss)
* [Manalyze](https://github.com/JusticeRage/Manalyze)

It's made with vanilla JS in Frontend and run [FastApi](https://pypi.org/project/fastapi/) python in Backend.

## How to use

Malstatic have two ways to install.

### Using Docker

You can use the latest docker image and run as a container.

```bash
docker pull adriann17/malstatic
docker run -d -p 7071:7071 malstatic
```

### Manual Instalation

Another alternative it's run as a python project. First you need to install [Radare2](https://github.com/radareorg/radare2), [Capa](https://github.com/mandiant/capa/blob/master/doc/installation.md), [Floss](https://github.com/mandiant/flare-floss/blob/master/doc/installation.md) and [Manalyze](https://github.com/JusticeRage/Manalyze#how-to-build) in your machine. Read the installation guides to know more about.


After that, you can use those scripts to install required python dependencies and the project.
```bash
pip3 install uvicorn fastapi jinja2 python-multipart r2pipe
git clone https://github.com/AdrianN17/Malstatic.git
cd Malstatic 
python main.py
```