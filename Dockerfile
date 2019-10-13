FROM python:3

WORKDIR /usr/src/app/

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./src .
COPY swagger swagger
ENV PYTHONPATH "${PYTHONPATH}:/usr/src/app/"
ENV QG_DB_URI "mysql+pymysql://root:123456@mysql_qualys_guard:3306/qualys_guard"
ENV SWG_DIR "./swagger"

#CMD python app.py
CMD  uwsgi --http :8080 -w app -p 16
