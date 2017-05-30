FROM clojure

RUN apt-get update
RUN apt-get install -y make gcc

# build capstone
RUN git clone https://github.com/aquynh/capstone.git /tmp/capstone
RUN cd /tmp/capstone && ./make.sh && ./make.sh install

# build capstone-java bindings
RUN apt-get install -y libjna-java
RUN cd /tmp/capstone/bindings/java && make
