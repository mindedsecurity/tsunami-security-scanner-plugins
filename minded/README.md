# IMQ Minded Security Tsunami Plugins

This directory contains all Tsunami plugins published by
[IMQ Minded Security](https://mindedsecurity.com/).

## Currently released plugins

### Detectors

*   [Plugin Name](link)

## Build all plugins

Use the following command to build all IMQ Minded Security released plugins:

```
./build_all.sh
```

All generated `jar` files are copied into `build/plugins` folder.

## INTERNAL: Build pipeline

Questa sezione non deve essere presente nel commit finale. È utilizzata per descrivere la pipeline di development utilizzata da IMQ Minded Security per lo sviluppo dei plugin.

-----

Prima di iniziare, bisogna avere la seguente struttura nel file system, che può essere inserita all'interno di una cartella `tsunami` che contiene 

```
.
├── compile.sh
├── logs
├── plugins
├── repos
│   └── tsunami-security-scanner-plugins
├── run.sh
├── tsunami-base
│   └── Dockerfile
└── tsunami-builder
    └── Dockerfile

9 directories, 8 files
```

dove `tsunami-security-scanner-plugins` è ottenuto effettuando il clone della seguente repository

```
git clone https://github.com/mindedsecurity/tsunami-security-scanner-plugins
```

mentre il contenuti degli script `run.sh` e `compile.sh` e il contenuto dei dockerfile sarà riportato a seguire.

-----

Per continuare è necessario creare due docker container, chiamati rispettivamente `tsunami` e `tsunami-builder`. Il docker `tsunami` conterrà il processo dello scanner, e sarà dunque utilizzato per effettuare gli scan, mentre  `tsunami-builder` conterrà gli strumenti per compilare i vari plugin. Entrambi questi docker dovranno condividere l'interfaccia di rete con l'host, quindi sarà necessaria la flag `--network="host"`. Per condividere le tra i docker e l'host saranno montati dei volumi con `-v`.

Seguono le istruzioni per buildare le immagini. Entambi i comandi di
build devono essere eseguiti a partire dalla cartella principale.

- Il docker `tsunami` può essere ottenuto a partire dal seguente `Dockerfile`, da salvare in `tsunami-base/Dockerfile`.
  
```dockerfile
FROM adoptopenjdk/openjdk13:debianslim

# Install dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/share/doc && rm -rf /usr/share/man \
 && apt-get clean

WORKDIR /usr/tsunami/repos

# Clone the tsunami scanner repo 
RUN git clone --depth 1 "https://github.com/google/tsunami-security-scanner"

# Compile the Tsunami scanner
WORKDIR /usr/tsunami/repos/tsunami-security-scanner
RUN ./gradlew shadowJar \
    && cp "$(find "./" -name "tsunami-main-*-cli.jar")" /usr/tsunami/tsunami.jar \
    && cp ./tsunami.yaml /usr/tsunami

# Stage 2: Release
FROM adoptopenjdk/openjdk13:debianslim-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ncrack ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/share/doc && rm -rf /usr/share/man \
    && apt-get clean \
    && mkdir logs/

WORKDIR /usr/tsunami

COPY --from=0 /usr/tsunami /usr/tsunami
```
  
  Per buildare eseguire il seguente comando nella cartella in cui è salvato il `Dockerfile`. 
  Prima di buildare posizionarsi nella cartella `tsunami-base`.
  
  ```
  docker build --no-cache -t tsunami -f tsunami-base/Dockerfile  .
  ```

- Il docker `tsunami-builder` può essere ottenuto a partire dal seguente `Dockerfile`. 
  
```dockerfile
FROM adoptopenjdk/openjdk13:debianslim

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/share/doc && rm -rf /usr/share/man \
 && apt-get clean

WORKDIR /usr/tsunami/

# build only basic fingerprinters and portscan plugins
RUN git clone --depth 1 "https://github.com/google/tsunami-security-scanner-plugins"
WORKDIR /usr/tsunami/tsunami-security-scanner-plugins/google
RUN rm -rf detectors
RUN chmod +x build_all.sh && ./build_all.sh

# build minded plugins
# NOTE: be sure to do a 'git pull https://github.com/google/tsunami-security-scanner' before.
COPY ./repos/tsunami-security-scanner-plugins/minded /usr/tsunami/minded
WORKDIR /usr/tsunami/minded
RUN chmod +x ./build_all.sh && ./build_all.sh

# Copy google plugins into minded
RUN cp /usr/tsunami/tsunami-security-scanner-plugins/google/build/plugins/*.jar /usr/tsunami/minded/build/plugins/

CMD ["bash"]
```

   Per buildare eseguire il seguente comando nella cartella in cui è salvato il `Dockerfile`
   
   ```
   docker build --no-cache -t tsunami-builder -f tsunami-builder/Dockerfile  .
   ```
   
	NOTA BENE: Prima di buildare posizionarsi nella **cartella precedente** alla `tsunami-builder`.   

A questo punto è possibile far partire i due container. Assicurarsi di creare le cartelle condivise `logs` e `plugins`.

- Il container `tsunami` lo si esegue con il seguente comando

```
docker run --name tsunami --rm -dit --network="host" -v "$(pwd)/logs":/usr/tsunami/logs -v "$(pwd)/plugins":/usr/tsunami/plugins tsunami 
```

- Il container `tsunami-builder` lo si esegue con il seguente comando

```
docker run --name tsunami-builder --rm -dit --network="host" -v "$(pwd)/repos/tsunami-security-scanner-plugins/minded/":"/usr/tsunami/minded" tsunami-builder
```

-----

Una volta che entrambi i docker sono stati eseguiti, è possibile
modificare il codice lavorando nella cartella
`repos/tsunami-security-scanner-plugins/minded`

Per triggare la compilazione basterà eseguire lo script `./compile.sh`,
che deve avere il seguente contenuto

```bash
#!/usr/bin/env sh

# TODO: if the tsunami-builder docker is not running, execute it

echo "[INFO] - Building plugins"
echo "-------------------------------------"

# get inside the tsunami-builder docker and build the plugins
docker exec -it tsunami-builder bash -c "cd /usr/tsunami/minded && ./build_all.sh"

echo "[INFO] - Copying minded plugins into tsunami"
echo "-------------------------------------"

cp repos/tsunami-security-scanner-plugins/minded/build/plugins/*.jar plugins/
```

Per effettuare lo scan con i nuovi plugin è necessario eseguire lo script `./run.sh`,
che deve avere il seguente contenuto

```bash
#!/usr/bin/env sh

# TODO: if the tsunami docker is not running, execute it

tsunami_scan_cmd() {
    echo "java -cp tsunami.jar:plugins/* -Dtsunami.config.location=tsunami.yaml \\"
    echo "   com.google.tsunami.main.cli.TsunamiCli \\"
    echo "   --ip-v4-target=127.0.0.1 \\"
    echo "   --scan-results-local-output-format=JSON \\"
    echo "   --scan-results-local-output-filename=logs/tsunami-output.json"
}

echo "[INFO] - Executing Tsunami scan"
echo "Main CMD:"
echo "$(tsunami_scan_cmd)"
echo ""
echo "Plugin list:"
echo "$(ls -1 plugins/*.jar)"
echo ""
echo "-------------------------------------"

docker exec -it tsunami bash -c "cd /usr/tsunami/ && $(tsunami_scan_cmd)"
```
Combinando i due script è possibile compilare ed eseguire

```
./compile.sh && ./run.sh
```
