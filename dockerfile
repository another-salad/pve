FROM mcr.microsoft.com/powershell:7.3-debian-bullseye-slim

COPY /prox.cluster.ca/* /usr/local/share/ca-certificates/

RUN update-ca-certificates

RUN mkdir ps
WORKDIR /ps

ENTRYPOINT [ "pwsh" ]
