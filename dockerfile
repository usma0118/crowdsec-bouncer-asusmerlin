# Use a lightweight base image for Python
FROM python:3.13-alpine
# Install Tini
RUN apk update && apk add --no-cache tini && apk add --no-cache openssh-client ca-certificates bash tzdata && \
    pip install --no-cache-dir coloredlogs && \
    update-ca-certificates

# Set environment variables for security and consistent behavior
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    date_format='%a, %d %b %Y %H:%M:%S GMT'
# Set the working directory
WORKDIR /app

# Copy only necessary files to reduce image size
COPY pyproject.toml /app/
COPY poetry.lock /app/

# Install dependencies using Poetry
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi && \
    rm poetry.lock

# Copy the application code and set ownership in one step
COPY --chown=nobody:nogroup *.py /app/

# Switch to the 'nobody' user
USER nobody:nogroup
# Use Tini as the entrypoint
ENTRYPOINT ["/sbin/tini", "--"]
# Specify the command to run the application
CMD ["python", "main.py"]
