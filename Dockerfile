FROM python:3

WORKDIR /usr/src/app/

COPY requirements.txt .
COPY ./src .
COPY openapi openapi

ENV PYTHONPATH "${PYTHONPATH}:/usr/src/app/"
ENV QG_DB_URI "mysql+pymysql://root:123456@mysql_qualys_guard:3306/qualys_guard"
ENV OPENAPI_DIR "./openapi"

RUN  pip install --no-cache-dir -r requirements.txt

CMD  python check_connection.py && uwsgi --http :8080 -w app --threads 16 --master
