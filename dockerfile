FROM mcr.microsoft.com/powershell:7.3-debian-bullseye-slim

COPY /prox.cluster.ca/* /usr/local/share/ca-certificates/

RUN update-ca-certificates

# Install Microsoft.PowerShell.SecretStore and SecretManagement
RUN Install-Module -Name Microsoft.PowerShell.SecretStore -Force -AllowClobber
RUN Install-Module -Name Microsoft.PowerShell.SecretManagement -Force -AllowClobber

RUN mkdir ps
WORKDIR /ps

ENTRYPOINT [ "pwsh" ]
