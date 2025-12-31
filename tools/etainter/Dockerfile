# Pull base image
FROM python:3.8-slim

RUN apt-get update; apt-get install -y git build-essential

# Clone the repository
RUN git clone https://github.com/DependableSystemsLab/eTainter.git
WORKDIR /eTainter

RUN python3 -m pip install -r requirements.txt

ENTRYPOINT [ "python3", "bin/analyzer.py" ]