FROM node:14 as builder
COPY . /tokenendpoint
WORKDIR /tokenendpoint
RUN npm install
FROM node:14
COPY --from=builder /tokenendpoint /tokenendpoint
WORKDIR /tokenendpoint
EXPOSE 3000/tcp
CMD ["node", "index.js"]

