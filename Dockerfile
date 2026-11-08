FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY KnifeStyleLicenseServer.csproj ./
COPY . ./
RUN dotnet publish KnifeStyleLicenseServer.csproj -c Release -o /out

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /out ./
ENV KNIFESTYLE_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "dotnet KnifeStyleLicenseServer.dll --urls http://0.0.0.0:${PORT:-8080}"]

