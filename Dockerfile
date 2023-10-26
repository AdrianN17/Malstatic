FROM debian:latest

RUN apt-get update && apt-get install -y \
    python3 \
    pip \
    libboost-regex-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libboost-filesystem-dev \
    libssl-dev \
    build-essential  \
    cmake \
    git \
    wget \
    unzip


RUN wget -O capa.zip https://github.com/mandiant/capa/releases/download/v6.1.0/capa-v6.1.0-linux.zip && unzip capa.zip && rm capa.zip && chmod +x capa && mv capa /usr/local/bin/

RUN wget -O floss.zip https://github.com/mandiant/flare-floss/releases/download/v2.3.0/floss-v2.3.0-linux.zip && unzip floss.zip && rm floss.zip && chmod +x floss && mv floss /usr/local/bin/

RUN git clone --recursive https://github.com/mandiant/capa.git

RUN pip3 install uvicorn fastapi jinja2 python-multipart r2pipe --break-system-packages

RUN git clone https://github.com/JusticeRage/Manalyze.git && cd Manalyze && cmake . && make -j5 && make install && cd ..

RUN git clone https://github.com/radareorg/radare2 && cd radare2 ; sys/install.sh && cd ..

RUN git clone https://github.com/AdrianN17/Malstatic /app

WORKDIR /app

EXPOSE 7071

CMD ["python3", "main.py"]