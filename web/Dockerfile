FROM python:3.10
WORKDIR /usr/src/app
COPY requirements.txt ./
COPY en_core_web_sm-3.7.1.tar.gz ./
RUN pip install --no-cache-dir -r requirements.txt
COPY en_core_web_sm-3.7.1.tar.gz ./
RUN pip install ./en_core_web_sm-3.7.1.tar.gz
COPY . .
CMD ["python", "app.py"]
