ARG base_tag=2.1.6-runtime-nanoserver-1809
FROM microsoft/dotnet:${base_tag}

USER ContainerAdministrator

RUN reg add hklm\system\currentcontrolset\services\cexecsvc /v ProcessShutdownTimeoutSeconds /t REG_DWORD /d 60 && \
    reg add hklm\system\currentcontrolset\control /v WaitToKillServiceTimeout /t REG_SZ /d 60000 /f

RUN setx /M PATH "%PATH%;%ProgramFiles%\\dotnet"

ARG EXE_DIR=.

WORKDIR /app

COPY $EXE_DIR/ ./

ENV IPInterfaceName vEthernet (Ethernet)

USER ContainerUser

CMD ["dotnet", "Microsoft.Azure.Devices.Edge.Agent.Service.dll"]
