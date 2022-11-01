FROM node
VOLUME /bin/nametag/keystore
COPY * /bin/nametag
WORKDIR /bin/nametag
RUN yarn install
