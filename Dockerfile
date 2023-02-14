FROM ubuntu:20.04
ENV VERSION 10.2.2
ENV DOWNLOAD_URL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.2_build/ghidra_10.2.2_PUBLIC_20221115.zip
WORKDIR /opt/
COPY . /opt/
ENV TZ=America/New_York
ARG GID=1000
ARG UID=1000
ARG USER=guser
# directories for Ghidra Scripts
RUN mkdir /analysis /binaries /submissions /core-scripts /glogdir  && \
    apt-get update -y &&  apt-get install -yq tzdata; ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get install -y curl unzip openjdk-17-jre-headless openjdk-17-jdk python3 python3-pip libyara3 yara && \
    python3 -m pip install -r requirements.txt && \
    groupadd -g $GID -o $USER && \
    useradd -ms /bin/bash -u $UID -g $GID $USER && \
    ln -s /usr/local/lib/python3.8/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so && \
    curl -Lk -o /tmp/ghidra.zip $DOWNLOAD_URL && \
    unzip /tmp/ghidra.zip -d /tmp && \
    mv /tmp/ghidra_${VERSION}_PUBLIC/ /ghidra

USER guser
ENV PATH=$PATH:/analysis:/binaries:/submissions:/core-scripts:/repos:/ghidra/support
ENV RABBITMQ_QUEUE "GhidraGolf"
ENV RABBITMQ_HOST "rabbitmq"
CMD ["python3", "./app/consumer.py"]
