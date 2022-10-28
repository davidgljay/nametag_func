FROM node
VOLUME /bin/nametag/keystore
COPY *.py /bin/nametag
WORKDIR /bin/nametag
RUN pip install
