FROM python
VOLUME /bin/nametag/keystore
COPY *.py /bin/nametag
WORKDIR /bin/nametag
