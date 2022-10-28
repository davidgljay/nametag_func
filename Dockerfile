FROM python
VOLUME /bin/nametag/keystore
COPY * /bin/nametag
WORKDIR /bin/nametag
