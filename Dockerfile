FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env

COPY . ./app

WORKDIR /app/demo/WebAuthn.Net.Demo.Mvc

RUN dotnet restore
RUN dotnet publish -c Release -o out

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build-env /app/demo/WebAuthn.Net.Demo.Mvc/out .
ENTRYPOINT ["dotnet", "WebAuthn.Net.Demo.Mvc.dll"]